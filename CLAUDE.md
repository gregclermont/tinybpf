# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

tinybpf is a minimal Python library for loading and interacting with pre-compiled CO-RE (Compile Once, Run Everywhere) eBPF programs. It uses ctypes bindings to a bundled libbpf shared library, with no runtime dependencies except libelf (typically pre-installed on Linux systems).

## Local Development

The Makefile auto-detects OS and runs commands appropriately (directly on Linux, via Lima VM on macOS).

```bash
# Compile eBPF test programs (uses Docker, works anywhere)
make compile

# Download libbpf and run tests
make test

# Or separately:
make setup   # Download libbpf
make clean   # Remove compiled eBPF objects
```

### macOS Setup (one-time)

On macOS, tests run inside a Lima VM since eBPF requires Linux.

```bash
# Install Lima if needed
brew install lima

# Create and configure the VM (one-time)
make lima-create

# Then use normal commands - they auto-route to Lima
make test
```

### Running Individual Tests

```bash
# On Linux
uv run pytest tests/test_api.py -v
uv run pytest tests/test_load.py::test_load_minimal -v

# On macOS - drop into Lima shell, then run pytest directly
make lima-shell
uv run pytest tests/test_api.py -v
```

### CI/CD Commands

```bash
# Trigger CI with custom Python versions
gh workflow run ci.yml -f python-versions='["3.10", "3.11", "3.12"]'

# Create a release
gh workflow run release.yml -f version=0.2.0

# Build libbpf for new version
gh workflow run build-libbpf.yml -f libbpf_version=1.5.0
```

## Architecture

### Source Layout
```
src/tinybpf/
├── __init__.py          # Public API exports (load function, all types)
├── _object.py           # High-level wrapper classes (BpfObject, BpfProgram, BpfMap, BpfLink)
└── _libbpf/
    ├── __init__.py
    └── bindings.py      # Low-level ctypes bindings to libbpf C functions
```

### Key Design Patterns

1. **ctypes over cffi/Cython**: Zero build-time dependencies, pure Python wheels, simpler distribution. libbpf API is stable and small.

2. **Bundled libbpf, system libelf**: System libbpf versions vary too widely (need 1.4.0+), but libelf is stable and ubiquitous. Bundling libelf would require also bundling libzstd, liblzma, libbz2.

3. **Dict-like interfaces**: `BpfMap` supports `[]` access, iteration, `.items()`, `.keys()`, `.values()`. `ProgramCollection` and `MapCollection` provide dict-like access by name.

4. **Context managers**: `BpfObject` and `BpfLink` implement `__enter__`/`__exit__` for automatic resource cleanup.

5. **Error handling**: libbpf functions return `-errno` directly (not -1 with errno set via C library). Use `abs(ret)` to extract the error code, not `ctypes.get_errno()`. See `_check_err()` in `_object.py` for the canonical pattern.

### Test Requirements

- `test_api.py` and `test_version.py`: No special requirements
- `test_load.py`: Requires root/CAP_BPF privileges and compiled eBPF test programs in `tests/bpf/`

### CI/CD

- eBPF test programs (`tests/bpf/*.bpf.c`) are compiled using `ghcr.io/gregclermont/tinybpf-compile` Docker image
- Wheels are architecture-specific (manylinux_2_28_x86_64, manylinux_2_28_aarch64)
- libbpf version is pinned in `.libbpf-version` file
- See `WORKFLOWS.md` for detailed CI/CD workflow documentation
