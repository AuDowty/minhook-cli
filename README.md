# minhook-cli

Attach to a running Windows process and trace calls to a function — registers, return address, and a peek at the stack at hit time. Cross-process, no injection.

Pairs naturally with [`pe-info`](https://github.com/AuDowty/pe-info) (find the RVA you want to trace) and [`pdb-info`](https://github.com/AuDowty/pdb-info) (resolve the symbol).

## How it works

Uses the Windows Debug API (`DebugActiveProcess` + `WaitForDebugEvent`), not true inline hooks. We patch the target function's first byte with `INT3` (`0xCC`), catch the breakpoint, log register state, restore the byte, single-step, and re-arm. Same UX as MinHook for tracing — no length disassembly, no trampolines, no prologue stealing.

Tradeoff: the target sees itself as "being debugged" (`IsDebuggerPresent` returns true). Fine for dev/RE work; not for anti-debug scenarios.

## Install

```
cargo install --git https://github.com/AuDowty/minhook-cli
```

Requires Windows. Run as an Administrator if the target is.

## Use

Trace by absolute address:

```
minhook-cli --pid 1234 --addr 0x7ff67c001234
```

Trace by module + RVA (looked up via the process's loaded module list):

```
minhook-cli --pid 1234 --module mc.dll --rva 0x1b520
```

`Ctrl+C` detaches cleanly (restores the patched byte, calls `DebugActiveProcessStop`).

Output:

```
[hit  1] tid=18840  rip=0x7ff67c001234  ret=0x7ff67c00a981
         rcx=0x000000000000002a  rdx=0x000001f3a4c0e090
         r8 =0x0000000000000000  r9 =0x0000000000000010
         stack: 7ff67c00a981 0000000000000000 ...
```

## License

MIT.
