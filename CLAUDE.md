# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

tinybpf is a minimal Python library for loading and interacting with pre-compiled CO-RE (Compile Once, Run Everywhere) eBPF programs. It uses ctypes bindings to a bundled libbpf shared library, with no runtime dependencies except libelf (typically pre-installed on Linux systems).

## Development

See `DEVELOPMENT.md` for full setup, commands, and CI/CD workflow documentation.

**Quick reference:**
```bash
make test      # Run tests (auto-detects OS)
make compile   # Compile eBPF test programs
make check     # Run all code quality checks
```

## Architecture

### Source Layout
```
src/tinybpf/
├── __init__.py          # Public API exports
├── _types.py            # Exception, enums, dataclasses, error helpers
├── _link.py             # BpfLink class
├── _map.py              # BpfMap, MapCollection
├── _program.py          # BpfProgram, ProgramCollection
├── _buffers.py          # BpfRingBuffer, BpfPerfBuffer
├── _object.py           # BpfObject, load()
└── _libbpf/
    ├── __init__.py
    └── bindings.py      # Low-level ctypes bindings to libbpf C functions
```

### Key Design Patterns

1. **ctypes over cffi/Cython**: Zero build-time dependencies, pure Python wheels, simpler distribution. libbpf API is stable and small.

2. **Bundled libbpf, system libelf**: System libbpf versions vary too widely (need 1.4.0+), but libelf is stable and ubiquitous. Bundling libelf would require also bundling libzstd, liblzma, libbz2.

3. **Dict-like interfaces**: `BpfMap` supports `[]` access, iteration, `.items()`, `.keys()`, `.values()`. `ProgramCollection` and `MapCollection` provide dict-like access by name.

4. **Context managers**: `BpfObject` and `BpfLink` implement `__enter__`/`__exit__` for automatic resource cleanup.

5. **Error handling**: libbpf functions return `-errno` directly (not -1 with errno set via C library). Use `abs(ret)` to extract the error code, not `ctypes.get_errno()`. See `_check_err()` in `_types.py` for the canonical pattern.

## Test Requirements

- `test_api.py` and `test_version.py`: No special requirements
- `test_load.py`: Requires root/CAP_BPF privileges and compiled eBPF test programs in `tests/bpf/`

## CI/CD

- eBPF test programs (`tests/bpf/*.bpf.c`) are compiled using `ghcr.io/gregclermont/tinybpf-compile` Docker image
- Wheels are architecture-specific (manylinux_2_28_x86_64, manylinux_2_28_aarch64)
- libbpf version is pinned in `.libbpf-version` file

## Compiling and Debugging BPF Programs

### Compiling BPF Programs (macOS or Linux)

Use the Docker image to compile BPF programs:
```bash
# Compile a single file
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile tests/bpf/myprogram.bpf.c

# Compile all test BPF programs
make compile
```

### Inspecting BTF Information

On the lima VM (or any Linux with bpftool):
```bash
# Dump all BTF types
limactl shell tinybpf -- bpftool btf dump file tests/bpf/myprogram.bpf.o

# Search for a specific struct
limactl shell tinybpf -- bpftool btf dump file tests/bpf/myprogram.bpf.o | grep -A 10 "'mystruct'"
```

### Exporting Structs to BTF

Event structs used in ring/perf buffers are NOT automatically included in BTF.
To make a struct available for BTF validation, "anchor" it using one of:

```c
// Method 1: Global variable (recommended)
struct event _event_anchor __attribute__((unused));

// Method 2: BTF_TYPE_EMIT macro (if available in your vmlinux.h)
BTF_TYPE_EMIT(struct event);
```

### Running Python Scripts in Lima VM

```bash
# Run a Python script with sudo (required for BPF operations)
limactl shell tinybpf -- sudo python3 /path/to/script.py
```
