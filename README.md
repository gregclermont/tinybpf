# tinybpf

A minimal Python library for loading pre-compiled CO-RE eBPF programs.

[![PyPI version](https://badge.fury.io/py/tinybpf.svg)](https://badge.fury.io/py/tinybpf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`tinybpf` provides a Pythonic interface to [libbpf](https://github.com/libbpf/libbpf) for loading and interacting with pre-compiled eBPF programs. It bundles `libbpf.so` in the wheel, making it pip-installable without system dependencies.

**Note:** This library does not compile eBPF programs — that should be done separately with clang. This is purely for loading `.bpf.o` files compiled elsewhere.

## Installation

```bash
pip install tinybpf
```

## Quick Start

```python
import tinybpf

# Load a pre-compiled BPF object file
with tinybpf.load("program.bpf.o") as obj:
    # Attach a program to a kernel probe
    prog = obj.program("trace_connect")
    link = prog.attach_kprobe("tcp_v4_connect")

    # Read from a map
    for key, value in obj.maps["connections"].items():
        print(f"Key: {key.hex()}, Value: {value.hex()}")

# Resources are automatically cleaned up when exiting the context
```

## Features

- **Context managers** for automatic resource cleanup
- **Iterators** for map traversal
- **Type hints** throughout
- **Typed map access** with automatic serialization
- **Multiple attachment types**: kprobes, kretprobes, tracepoints, uprobes, raw tracepoints

## API Overview

### Loading BPF Objects

```python
import tinybpf

# Using context manager (recommended)
with tinybpf.load("program.bpf.o") as obj:
    # Work with the object
    pass

# Manual management
obj = tinybpf.load("program.bpf.o")
try:
    # Work with the object
    pass
finally:
    obj.close()
```

### Working with Programs

```python
with tinybpf.load("program.bpf.o") as obj:
    # Get a specific program
    prog = obj.program("my_function")

    # List all programs
    for prog in obj.programs:
        print(f"{prog.name}: {prog.type.name}")

    # Attach to various hooks
    link1 = prog.attach_kprobe("tcp_v4_connect")
    link2 = prog.attach_kretprobe("tcp_v4_connect")
    link3 = prog.attach_tracepoint("syscalls", "sys_enter_read")

    # Auto-attach based on section name
    link4 = prog.attach()

    # Detach when done
    link1.detach()
```

### Working with Maps

```python
import struct

with tinybpf.load("program.bpf.o") as obj:
    # Access maps by name
    counters = obj.maps["counters"]

    # Raw bytes access
    key = struct.pack("I", 0)
    value = struct.pack("Q", 100)
    counters[key] = value

    raw_value = counters[key]
    count = struct.unpack("Q", raw_value)[0]

    # Iterate over entries
    for key, value in counters.items():
        print(f"Key: {key.hex()}, Value: {value.hex()}")

    # Delete entries
    del counters[key]

    # Check existence
    if key in counters:
        print("Key exists")
```

### Typed Map Access

For convenience, you can create typed views of maps:

```python
with tinybpf.load("program.bpf.o") as obj:
    # Create a typed view with struct format strings
    typed_map = obj.maps["counters"].typed(
        key_format="I",    # uint32
        value_format="Q"   # uint64
    )

    # Now use Python types directly
    typed_map[0] = 100
    print(typed_map[0])  # 100

    for key, value in typed_map.items():
        print(f"Key: {key}, Value: {value}")  # Already unpacked

    # Using ctypes structures
    import ctypes

    class Key(ctypes.Structure):
        _fields_ = [("pid", ctypes.c_uint32)]

    class Value(ctypes.Structure):
        _fields_ = [("count", ctypes.c_uint64)]

    typed_map = obj.maps["per_pid"].typed(
        key_type=Key,
        value_type=Value
    )
```

### Map Properties

```python
with tinybpf.load("program.bpf.o") as obj:
    my_map = obj.maps["my_map"]

    print(f"Name: {my_map.name}")
    print(f"Type: {my_map.type.name}")  # HASH, ARRAY, etc.
    print(f"Key size: {my_map.key_size}")
    print(f"Value size: {my_map.value_size}")
    print(f"Max entries: {my_map.max_entries}")

    # Get all info as a dataclass
    info = my_map.info
    print(info)
```

### Link Management

```python
with tinybpf.load("program.bpf.o") as obj:
    prog = obj.program("trace_func")

    # Links can be used as context managers
    with prog.attach_kprobe("target_func") as link:
        print(f"Attached: {link.is_attached}")
        print(f"Hook: {link.hook_name}")
    # Automatically detached

    # Or managed manually
    link = prog.attach_kprobe("target_func")
    # ... do work ...
    link.detach()

    # Pin links to persist across process restarts
    link = prog.attach_kprobe("target_func")
    link.pin("/sys/fs/bpf/my_link")
    link.unpin()
```

## Exceptions

```python
from tinybpf import (
    BPFError,           # Base exception
    BPFLoadError,       # Failed to load object
    BPFVerifierError,   # BPF verifier rejected program
    BPFAttachError,     # Failed to attach program
    BPFMapError,        # Map operation failed
    BPFNotFoundError,   # Program or map not found
    BPFPermissionError, # Insufficient permissions
    BPFSyscallError,    # Low-level syscall failed
)
```

## Requirements

- Python 3.9+
- Linux kernel with BPF support
- Root privileges or CAP_BPF capability for most operations

## Compiling BPF Programs

This library loads pre-compiled BPF object files. To compile your BPF programs:

```bash
# Generate vmlinux.h (one time)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile your BPF program
clang -g -O2 -target bpf \
    -D__TARGET_ARCH_x86 \
    -c program.bpf.c \
    -o program.bpf.o
```

## Inspiration

The API design is inspired by:
- [cilium/ebpf](https://github.com/cilium/ebpf) (Go)
- [Aya](https://github.com/aya-rs/aya) (Rust)

The libbpf bundling approach is based on:
- [pybpfmaps](https://github.com/PeterStolz/pybpfmaps)

## License

MIT License - see [LICENSE](LICENSE) for details.
