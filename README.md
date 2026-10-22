# GhidraDosInterruptResolver

A Ghidra extension that identifies and annotates x86 DOS/BIOS interrupt calls (`INT nn`) in 16-bit Real Mode binaries using definitions from [Ralf Brown's Interrupt List](https://www.cs.cmu.edu/~ralf/files.html).

## Features

- Resolves register values (AH/AL) to determine the specific interrupt function,
  and checks any other registers an entry pins (e.g. `BX = 4D41h` for a TSR
  installation check) to choose between entries that share a function code
- Gives up rather than guessing: on AH/AX alone it only assumes a selector's
  standard service (the first RBIL entry from a trusted category, by default
  DOS, BIOS, video, mouse, memory managers, serial, Windows and CPU). Vendor
  entries and TSR install checks need a confirmed qualifier register;
  otherwise the call becomes `INTxxh_yy_UNKNOWN` with the candidates in a
  plate comment
- Adds plate and PRE comments (visible in the decompiler)
- Creates bookmarks for quick navigation
- Generates overlay functions with register-based prototypes, including far
  pointers in register pairs (`DS:DX`, `ES:BX`). The result struct merges every
  outcome RBIL lists (a register set only on error is still an output), adds
  CF or ZF where RBIL reports the outcome through them, and marks registers
  the call destroys as `clobberedN clobbered_REG` fields, so the decompiler
  doesn't assume the caller's value survives
- Overrides each INT as a direct call to its overlay function so the decompiler
  shows a typed call; program exits (INT 20h, 21h/00h, 21h/31h, 21h/4Ch, 27h)
  are marked non-returning
- Installs a program spec extension (`callotherfixup` for `swi`) that removes
  the leftover `swi(n)` statement in front of each overridden call

The call override and the `swi` fixup can be turned off in the analyzer
options; with overrides off, INT instructions get plain DATA references to
their overlay functions instead. The trusted category letters are the
"Trusted RBIL categories" option; add `c` for DOS PRINT on INT 2Fh, or `N`
for network clients.

## Build

Requires **Java 21** and a Ghidra installation.

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

The distribution zip is output to `dist/`.

## Install

1. Build the extension or grab a release zip
2. In Ghidra: **File > Install Extensions > +** and select the zip
3. Restart Ghidra

The analyzer runs automatically on x86 16-bit Real Mode programs during auto-analysis.

## Data

Interrupt definitions are provided via the [rbil-yaml](https://github.com/playday3008/rbil-yaml) git submodule at `data/rbil-yaml/`. The 256 YAML files (one per interrupt vector) are generated from Ralf Brown's Interrupt List Release 61 by [rbil-parser](https://github.com/playday3008/rbil-parser).

## License

See [LICENSE](LICENSE) for details.
