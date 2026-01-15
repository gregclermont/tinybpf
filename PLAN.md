# tinybpf

## Goal
Minimal Python library for loading and interacting with pre-compiled CO-RE eBPF programs.

## Philosophy
- **Minimal dependencies**: Only ctypes (stdlib) and bundled libbpf
- **Pythonic API**: Context managers, iterators, type hints, dataclasses
- **No compilation**: Loading `.bpf.o` files only, compilation is out of scope
- **Inspired by**: cilium/ebpf (Go), Aya (Rust) — but idiomatic Python

## API Overview

```python
import tinybpf

# Load a pre-compiled CO-RE eBPF object
with tinybpf.load("program.bpf.o") as obj:
    # Inspect programs and maps
    print(obj.name, obj.programs, obj.maps)

    # Attach programs to hooks
    link = obj.program("trace_connect").attach_kprobe("tcp_v4_connect")

    # Or use auto-attach based on section name
    link = obj.program("trace_openat").attach()

    # Access maps like dictionaries
    for key, value in obj.maps["connections"].items():
        print(key, value)

    # Map operations
    obj.maps["counters"][0] = b'\x01\x00\x00\x00\x00\x00\x00\x00'
    value = obj.maps["counters"][0]

# Resources automatically cleaned up
```

## Core Types

### Classes
- `BpfObject` - Loaded eBPF object file (context manager)
- `BpfProgram` - Individual program with attachment methods
- `BpfMap` - Map with dict-like interface and iteration
- `BpfLink` - Attachment handle (context manager)

### Collections
- `ProgramCollection` - Dict-like access to programs by name
- `MapCollection` - Dict-like access to maps by name

### Data Classes
- `ProgramInfo` - Program metadata (name, section, type)
- `MapInfo` - Map metadata (name, type, sizes, max_entries)

### Enums
- `BpfProgType` - Program types (KPROBE, TRACEPOINT, XDP, etc.)
- `BpfMapType` - Map types (HASH, ARRAY, RINGBUF, etc.)

## Constraints
- Installable via `uv add` / `uv --with` / inline script deps
- Wheel must bundle libbpf (required to load eBPF)
- Type hints throughout (py.typed marker included)
- Python 3.9+ compatibility

## Distribution
- Wheel = complete package (Python code + bundled libbpf.so)
- One wheel per arch in GitHub Release
- User picks URL for their arch:
  - `uv add https://github.com/.../releases/download/dev/tinybpf-...-x86_64.whl`
  - `uv add https://github.com/.../releases/download/dev/tinybpf-...-aarch64.whl`
- Rolling `dev` tag: force-updated on each push

## Build & CI
- libbpf.so: build from https://github.com/libbpf/libbpf (`make` in `src/`)

### Workflows
1. **build-libbpf** (manual trigger)
   - Build libbpf in manylinux container (per arch)
   - Upload to `libbpf-v1.x.x` release (permanent, no expiry)

2. **ci** (on any push)
   - **build** job (if src/** or pyproject.toml changed):
     - Matrix: [x86_64, aarch64]
     - Download libbpf from `libbpf-v1.x.x` release (per arch)
     - Build wheel → one per arch (manylinux_2_28_*)
     - Upload all to `dev` release
   - **test** job (always, needs build if it ran):
     - `astral-sh/setup-uv@v4`
     - `uv pip install <wheel-url> && uv run pytest`

## Design Decisions

### Why ctypes over cffi/Cython?
- Zero build-time dependencies
- Pure Python wheels (no compilation needed)
- Simpler distribution
- libbpf API is stable and small

### Why bundle libbpf but not libelf?
- System libbpf versions vary widely (Ubuntu 22.04 has 0.5.0, we need 1.4.0+)
- libelf is stable, ubiquitous, and has minimal dependencies
- Bundling libelf would require bundling libzstd, liblzma, libbz2

### Error handling
- `BpfError` exception with errno for all libbpf failures
- `FileNotFoundError` for missing .bpf.o files
- `KeyError` for missing programs/maps (dict-like behavior)
