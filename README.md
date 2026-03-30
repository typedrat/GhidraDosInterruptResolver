# GhidraDosInterruptResolver

A Ghidra extension that identifies and annotates x86 DOS/BIOS interrupt calls (`INT nn`) in 16-bit Real Mode binaries using definitions from [Ralf Brown's Interrupt List](https://www.cs.cmu.edu/~ralf/files.html).

## Features

- Resolves register values (AH/AL) to determine the specific interrupt function
- Adds plate and PRE comments (visible in the decompiler)
- Creates bookmarks for quick navigation
- Generates overlay functions with register-based prototypes
- Adds navigable DATA references from INT instructions to overlay stubs

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

Interrupt definitions live in `data/interrupts/` (256 YAML files, one per vector). Generated from Ralf Brown's Interrupt List Release 61 by [rbil-parser](https://github.com/playday3008/rbil-parser). Pre-generated YAML files are also available at [rbil-yaml](https://github.com/playday3008/rbil-yaml).

## License

See [LICENSE](LICENSE) for details.
