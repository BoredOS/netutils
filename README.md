# BoredOS Network Utilities (netutils)

This repository packages basic diagnostic and network client command utilities for BoredOS.

## Decoupled Building

This repository is designed to compile **either within the main BoredOS tree OR completely standalone**.

### 1. Integrated Build (Within BoredOS)
If built from the BoredOS root tree, the build system passes `BOREDOS_SDK` to the Makefile. It immediately compiles these network client ELFs against the shared pre-built SDK:
```bash
make BOREDOS_SDK=/path/to/shared/sdk
```

### 2. Standalone Build (Isolated Clone)
If cloned completely separately in isolation, running `make` will **automatically bootstrap standard dependencies**:
```bash
make
```
If `build/sdk` is missing, the Makefile automatically clones the pure standard library dependency from `https://github.com/boredos/libc.git`, compiles it, installs it to `build/sdk`, and builds all network utilities standalone!

## Staging Installation
To stage the compiled executables into your target initrd root filesystem directory:
```bash
make DESTDIR=/path/to/initrd/root install
```
- All compiled binaries (`*.elf`) are routed to `/bin/`
