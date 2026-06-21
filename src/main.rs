#![cfg(target_os = "windows")]
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::mem;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use windows::core::PCSTR;
use windows::Win32::Foundation::{
    CloseHandle, BOOL, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, NTSTATUS,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, ReadProcessMemory,
    WaitForDebugEvent, WriteProcessMemory, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT,
};

const DBG_CONTINUE: NTSTATUS = NTSTATUS(0x00010002u32 as i32);
const DBG_EXCEPTION_NOT_HANDLED: NTSTATUS = NTSTATUS(0x80010001u32 as i32);
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | (CONTEXT_AMD64 | 0x8);
const CTX_SIZE: usize = 1232;
const OFF_FLAGS: usize = 0x30;
const OFF_EFLAGS: usize = 0x44;
const OFF_RCX: usize = 0x80;
const OFF_RDX: usize = 0x88;
const OFF_RSP: usize = 0x98;
const OFF_R8: usize = 0xB8;
const OFF_R9: usize = 0xC0;
const OFF_RIP: usize = 0xF8;

#[repr(C, align(16))]
struct Ctx([u8; CTX_SIZE]);

impl Ctx {
    fn new(flags: u32) -> Self {
        let mut c = Self([0u8; CTX_SIZE]);
        c.write_u32(OFF_FLAGS, flags);
        c
    }
    fn read_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.0[off..off + 4].try_into().unwrap())
    }
    fn read_u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.0[off..off + 8].try_into().unwrap())
    }
    fn write_u32(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn write_u64(&mut self, off: usize, v: u64) {
        self.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn rip(&self) -> u64 { self.read_u64(OFF_RIP) }
    fn set_rip(&mut self, v: u64) { self.write_u64(OFF_RIP, v) }
    fn rsp(&self) -> u64 { self.read_u64(OFF_RSP) }
    fn rcx(&self) -> u64 { self.read_u64(OFF_RCX) }
    fn rdx(&self) -> u64 { self.read_u64(OFF_RDX) }
    fn r8(&self)  -> u64 { self.read_u64(OFF_R8) }
    fn r9(&self)  -> u64 { self.read_u64(OFF_R9) }
    fn eflags(&self) -> u32 { self.read_u32(OFF_EFLAGS) }
    fn set_eflags(&mut self, v: u32) { self.write_u32(OFF_EFLAGS, v) }
}

#[link(name = "kernel32")]
extern "system" {
    fn GetThreadContext(hthread: HANDLE, lpcontext: *mut u8) -> BOOL;
    fn SetThreadContext(hthread: HANDLE, lpcontext: *const u8) -> BOOL;
}
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

#[derive(Parser)]
#[command(
    name = "minhook-cli",
    version,
    about = "Trace calls to a function in a running Windows process"
)]
struct Cli {
    #[arg(long)]
    pid: u32,
    #[arg(long, value_parser = parse_hex_usize, conflicts_with_all = ["module", "rva"])]
    addr: Option<usize>,
    #[arg(long, requires = "rva")]
    module: Option<String>,
    #[arg(long, value_parser = parse_hex_u32, requires = "module")]
    rva: Option<u32>,
    #[arg(long, default_value_t = 8)]
    stack_words: usize,
    #[arg(long)]
    max_hits: Option<u64>,
}

fn parse_hex_usize(s: &str) -> Result<usize, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    usize::from_str_radix(s, 16).map_err(|e| format!("not a hex address: {e}"))
}
fn parse_hex_u32(s: &str) -> Result<u32, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).map_err(|e| format!("not a hex u32: {e}"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let target_addr = match cli.addr {
        Some(a) => a,
        None => {
            let module = cli.module.as_deref().ok_or("--addr or --module+--rva required")?;
            let rva = cli.rva.ok_or("--rva required with --module")?;
            let base = find_module_base(cli.pid, module)?;
            base + rva as usize
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_signal = stop.clone();
    ctrlc_set(move || stop_signal.store(true, Ordering::SeqCst))?;

    let proc = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            false,
            cli.pid,
        )
    }
    .map_err(|e| format!("OpenProcess({}): {e}", cli.pid))?;
    let _g_proc = HandleGuard(proc);

    let original_byte = read_byte(proc, target_addr)?;
    write_byte(proc, target_addr, 0xCC)?;

    unsafe { DebugActiveProcess(cli.pid) }
        .map_err(|e| format!("DebugActiveProcess({}): {e}", cli.pid))?;
    let detach_pid = cli.pid;
    let detach = Detacher {
        proc,
        addr: target_addr,
        byte: original_byte,
        pid: detach_pid,
    };

    eprintln!(
        "attached to pid {} — INT3 armed at 0x{:x}; Ctrl+C to detach",
        cli.pid, target_addr
    );

    let mut hits: u64 = 0;
    let mut last_thread: Option<(u32, HANDLE)> = None;

    while !stop.load(Ordering::SeqCst) {
        let mut event: DEBUG_EVENT = unsafe { mem::zeroed() };
        if unsafe { WaitForDebugEvent(&mut event, 250) }.is_err() {
            continue;
        }

        let mut status = DBG_CONTINUE;
        match event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let exc = unsafe { event.u.Exception };
                let code = exc.ExceptionRecord.ExceptionCode;
                let addr = exc.ExceptionRecord.ExceptionAddress as usize;

                if code == EXCEPTION_BREAKPOINT && addr == target_addr {
                    hits += 1;
                    let thread = unsafe {
                        OpenThread(
                            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                            false,
                            event.dwThreadId,
                        )
                    }
                    .map_err(|e| format!("OpenThread({}): {e}", event.dwThreadId))?;

                    let mut ctx = Ctx::new(CONTEXT_FULL);
                    if unsafe { GetThreadContext(thread, ctx.0.as_mut_ptr()) }.0 == 0 {
                        return Err("GetThreadContext failed".into());
                    }

                    ctx.set_rip(ctx.rip().saturating_sub(1));

                    let ret = read_qword(proc, ctx.rsp() as usize).unwrap_or(0);
                    print_hit(hits, event.dwThreadId, ctx.rip(), ret, &ctx);
                    if cli.stack_words > 0 {
                        print_stack(proc, ctx.rsp() as usize, cli.stack_words);
                    }

                    write_byte(proc, target_addr, original_byte)?;
                    let ef = ctx.eflags();
                    ctx.set_eflags(ef | 0x100);
                    if unsafe { SetThreadContext(thread, ctx.0.as_ptr()) }.0 == 0 {
                        return Err("SetThreadContext failed".into());
                    }

                    if let Some((_, old)) = last_thread.replace((event.dwThreadId, thread)) {
                        unsafe {
                            let _ = CloseHandle(old);
                        }
                    }

                    if let Some(max) = cli.max_hits {
                        if hits >= max {
                            eprintln!("max-hits reached, detaching");
                            stop.store(true, Ordering::SeqCst);
                        }
                    }
                } else if code == EXCEPTION_SINGLE_STEP {
                    write_byte(proc, target_addr, 0xCC)?;
                    if let Some((_, h)) = last_thread.take() {
                        unsafe {
                            let _ = CloseHandle(h);
                        }
                    }
                } else if code == EXCEPTION_BREAKPOINT {
                    // initial loader breakpoint or unrelated INT3 — pass through
                } else {
                    status = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                eprintln!("target exited");
                break;
            }
            _ => {}
        }

        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) }
            .map_err(|e| format!("ContinueDebugEvent: {e}"))?;
    }

    drop(detach);
    eprintln!("done — {hits} hit(s)");
    Ok(())
}

struct Detacher {
    proc: HANDLE,
    addr: usize,
    byte: u8,
    pid: u32,
}

impl Drop for Detacher {
    fn drop(&mut self) {
        let _ = write_byte(self.proc, self.addr, self.byte);
        unsafe {
            let _ = DebugActiveProcessStop(self.pid);
        }
    }
}

fn ctrlc_set<F: Fn() + Send + Sync + 'static>(f: F) -> Result<(), String> {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    static mut HANDLER: Option<Box<dyn Fn() + Send + Sync>> = None;
    unsafe extern "system" fn dispatch(_ctrl_type: u32) -> BOOL {
        if let Some(h) = HANDLER.as_ref() {
            h();
        }
        BOOL(1)
    }
    unsafe {
        HANDLER = Some(Box::new(f));
        SetConsoleCtrlHandler(Some(dispatch), true)
            .map_err(|e| format!("SetConsoleCtrlHandler: {e}"))?;
    }
    Ok(())
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn read_byte(proc: HANDLE, addr: usize) -> Result<u8, String> {
    let mut b = 0u8;
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(proc, addr as *const c_void, &mut b as *mut _ as *mut c_void, 1, Some(&mut n))
    }
    .map_err(|e| format!("ReadProcessMemory at 0x{addr:x}: {e}"))?;
    if n != 1 {
        return Err(format!("short read at 0x{addr:x}"));
    }
    Ok(b)
}

fn write_byte(proc: HANDLE, addr: usize, b: u8) -> Result<(), String> {
    let mut n = 0usize;
    unsafe {
        WriteProcessMemory(
            proc,
            addr as *mut c_void,
            &b as *const _ as *const c_void,
            1,
            Some(&mut n),
        )
    }
    .map_err(|e| format!("WriteProcessMemory at 0x{addr:x}: {e}"))?;
    if n != 1 {
        return Err(format!("short write at 0x{addr:x}"));
    }
    Ok(())
}

fn read_qword(proc: HANDLE, addr: usize) -> Result<u64, String> {
    let mut buf = [0u8; 8];
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            proc,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            8,
            Some(&mut n),
        )
    }
    .map_err(|e| format!("ReadProcessMemory at 0x{addr:x}: {e}"))?;
    if n != 8 {
        return Err(format!("short read at 0x{addr:x}"));
    }
    Ok(u64::from_le_bytes(buf))
}

fn print_hit(n: u64, tid: u32, rip: u64, ret: u64, ctx: &Ctx) {
    println!(
        "[hit {n:>3}] tid={tid}  rip=0x{rip:016x}  ret=0x{ret:016x}\n         rcx=0x{:016x}  rdx=0x{:016x}\n         r8 =0x{:016x}  r9 =0x{:016x}",
        ctx.rcx(), ctx.rdx(), ctx.r8(), ctx.r9()
    );
}

fn print_stack(proc: HANDLE, rsp: usize, words: usize) {
    let mut bytes = vec![0u8; words * 8];
    let mut n = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            proc,
            rsp as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            bytes.len(),
            Some(&mut n),
        )
    };
    if ok.is_err() {
        return;
    }
    let read = n / 8;
    let mut line = String::from("         stack: ");
    for i in 0..read {
        let w = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        line.push_str(&format!("{:016x} ", w));
    }
    println!("{}", line.trim_end());
}

fn find_module_base(pid: u32, name: &str) -> Result<usize, String> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) }
        .map_err(|e| format!("snapshot pid {pid}: {e}"))?;
    let _g = HandleGuard(snap);

    let mut me: MODULEENTRY32W = unsafe { mem::zeroed() };
    me.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

    let mut ok = unsafe { Module32FirstW(snap, &mut me) }.is_ok();
    let want = name.to_ascii_lowercase();
    while ok {
        let n_len = me
            .szModule
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(me.szModule.len());
        let mod_name = String::from_utf16_lossy(&me.szModule[..n_len]);
        if mod_name.to_ascii_lowercase() == want
            || mod_name.to_ascii_lowercase() == format!("{want}.dll")
        {
            return Ok(me.modBaseAddr as usize);
        }
        ok = unsafe { Module32NextW(snap, &mut me) }.is_ok();
    }
    Err(format!("module not found in pid {pid}: {name}"))
}

unsafe fn _silence_pcstr_unused() {
    let _ = PCSTR::null();
}
