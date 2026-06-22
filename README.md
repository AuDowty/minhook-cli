# minhook-cli

Trace function calls in a running Windows process — registers, return address, stack peek. Cross-process, no injection required.

Uses the Windows Debug API (`DebugActiveProcess` + INT3 breakpoints), not true inline hooks.

Pairs with [pe-info](https://github.com/AuDowty/pe-info) (find the RVA) and [pdb-info](https://github.com/AuDowty/pdb-info) (resolve the symbol).

## Install

```
cargo install --git https://github.com/AuDowty/minhook-cli
```

Windows only. Run as admin if the target is elevated.

## Use

```
minhook-cli --pid 1234 --addr 0x7ff67c001234
minhook-cli --pid 1234 --module foo.dll --rva 0x1b520
```

`Ctrl+C` detaches cleanly.

## License

MIT
