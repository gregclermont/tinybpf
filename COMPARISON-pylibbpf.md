# tinybpf vs pylibbpf: Feature Comparison

This document provides an in-depth comparison between **tinybpf** and **pylibbpf**, two Python libraries for interacting with eBPF programs.

## Executive Summary

| Aspect | tinybpf | pylibbpf |
|--------|---------|----------|
| **Binding Approach** | ctypes (pure Python) | pybind11 (C++ extension) |
| **Build Requirements** | None (pure Python wheels) | Wheels for x86_64; build from source for ARM |
| **Python Version** | 3.10+ | 3.12+ (wheels), 3.8+ (source) |
| **libbpf Version** | 1.4.0 (bundled) | Latest (git submodule) |
| **CO-RE Support** | Yes | No explicit support |
| **Ring Buffer** | Full support | Not implemented |
| **Perf Buffer** | Full support | Full support |
| **Async Support** | Yes (asyncio) | No |
| **Production Ready** | Yes | Alpha (0.0.7) |
| **Project Status** | Active | Under development |

---

## 1. Architecture & Binding Approach

### tinybpf
- **Pure Python with ctypes** - Zero build-time dependencies
- Bundled libbpf.so.1 (version 1.4.0) in architecture-specific wheels
- System libelf required at runtime
- Wheels available for: `manylinux_2_28_x86_64`, `manylinux_2_28_aarch64`

**Advantages:**
- No compilation needed during installation
- Simple `pip install` on any compatible system
- Easier debugging and contribution

### pylibbpf
- **pybind11 C++ bindings** - Native C++ extension
- libbpf as git submodule (statically linked)
- **Pre-built wheels available** on PyPI for Python 3.12+, x86_64 only
- Build from source required for ARM64 or older Python versions (CMake 4.0+, C++20 compiler)

**Advantages:**
- Potentially faster for performance-critical operations
- Direct memory access without Python overhead
- Can leverage C++ optimizations

**Wheel Limitations:**
- No ARM64/aarch64 wheels (removed in commit 84c9da9)
- Only Python 3.12 and 3.13 supported via wheels
- Users on ARM or Python 3.8-3.11 must build from source

---

## 2. Public API Comparison

### Loading BPF Objects

| Feature | tinybpf | pylibbpf |
|---------|---------|----------|
| Load function | `tinybpf.load(path)` | `BpfObject(path, structs={})` |
| Auto-load | Yes (on `load()`) | Manual `.load()` call |
| Context manager | Yes (`with load(...) as obj:`) | No |
| Struct definitions | Not required | Optional dict parameter |

**tinybpf:**
```python
import tinybpf
with tinybpf.load("program.bpf.o") as obj:
    # object auto-closes on exit
    pass
```

**pylibbpf:**
```python
import pylibbpf
obj = pylibbpf.BpfObject("program.o", structs={})
obj.load()
# manual cleanup needed
```

### Program Access

| Feature | tinybpf | pylibbpf |
|---------|---------|----------|
| List programs | `obj.programs` (collection) | `obj.get_program_names()` |
| Get by name | `obj.program("name")` | `obj.get_program("name")` |
| Dict-like access | `obj.programs["name"]` | No |
| Iteration | `for p in obj.programs:` | Manual iteration |

### Program Attachment

| Attachment Type | tinybpf | pylibbpf |
|-----------------|---------|----------|
| Auto-attach | `prog.attach()` | `prog.attach()` |
| Attach all | `obj.programs.attach_all()` | `obj.attach_all()` |
| Kprobe | `prog.attach_kprobe(func)` | Auto via section |
| Kretprobe | `prog.attach_kretprobe(func)` | Auto via section |
| Tracepoint | `prog.attach_tracepoint(cat, name)` | Auto via section |
| Raw tracepoint | `prog.attach_raw_tracepoint(name)` | Auto via section |
| Uprobe | `prog.attach_uprobe(binary, offset)` | Auto via section |
| Uretprobe | `prog.attach_uretprobe(binary, offset)` | Auto via section |

**tinybpf** provides explicit attachment methods for fine-grained control, while **pylibbpf** relies on libbpf's auto-detection from section names.

### Map Access

| Feature | tinybpf | pylibbpf |
|---------|---------|----------|
| List maps | `obj.maps` (collection) | `obj.get_map_names()` |
| Get by name | `obj.map("name")` | `obj.get_map("name")` or `obj["name"]` |
| Dict-like access | `obj.maps["name"]` | `obj["name"]` |
| Generic typing | `BpfMap[KT, VT]` | No |

### Map Operations

| Operation | tinybpf | pylibbpf |
|-----------|---------|----------|
| Lookup | `map[key]`, `map.lookup(key)` | `map[key]`, `map.lookup(key)` |
| Update | `map[key] = value`, `map.update(key, value, flags)` | `map[key] = value`, `map.update(key, value)` |
| Delete | `del map[key]`, `map.delete(key)` | `del map[key]`, `map.delete_elem(key)` |
| Contains | `key in map` | No |
| Iteration | `for key in map:` | `map.get_next_key()` |
| Items | `map.items()` | `map.items()` |
| Keys | `map.keys()` | `map.keys()` |
| Values | `map.values()` | `map.values()` |
| Get with default | `map.get(key, default)` | No |
| Update flags | `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXIST` | No |

---

## 3. Map Types Support

### Supported Map Types Enumeration

| Map Type | tinybpf | pylibbpf |
|----------|---------|----------|
| HASH | Yes | Yes |
| ARRAY | Yes | Yes |
| PROG_ARRAY | Yes | Yes |
| PERF_EVENT_ARRAY | Yes | Yes (dedicated API) |
| PERCPU_HASH | Yes | Partial |
| PERCPU_ARRAY | Yes | Partial |
| STACK_TRACE | Yes | Partial |
| LRU_HASH | Yes | Yes |
| LPM_TRIE | Yes | Partial |
| RINGBUF | Yes (dedicated API) | No dedicated API |
| QUEUE | Yes | Partial |
| STACK | Yes | Partial |
| Total Types Defined | 32 | ~10 |

tinybpf enumerates all 32 BPF map types and provides generic dict-like access. pylibbpf focuses on the most common types.

---

## 4. Event Buffer Support

### Ring Buffer (RINGBUF)

| Feature | tinybpf | pylibbpf |
|---------|---------|----------|
| Dedicated class | `BpfRingBuffer` | None |
| Callback mode | Yes | N/A |
| Iterator mode | Yes (sync + async) | N/A |
| Multi-map support | Yes (`rb.add(map)`) | N/A |
| Zero-copy (memoryview) | Yes | N/A |
| Async iteration | Yes (`async for event in rb:`) | N/A |
| Event source tracking | Yes (`rb.events()` with map_name) | N/A |
| epoll_fd access | Yes | N/A |

**tinybpf Ring Buffer Example:**
```python
# Callback mode
rb = BpfRingBuffer(obj.map("events"), callback=lambda data: 0)
rb.poll(timeout_ms=1000)

# Iterator mode
rb = BpfRingBuffer(obj.map("events"))
rb.poll(timeout_ms=1000)
for event in rb:
    process(event)

# Async mode
async for event in rb:
    await process(event)
```

### Perf Buffer (PERF_EVENT_ARRAY)

| Feature | tinybpf | pylibbpf |
|---------|---------|----------|
| Dedicated class | `BpfPerfBuffer` | `PerfEventArray` |
| Sample callback | Yes (cpu, data) | Yes (cpu, data) |
| Lost callback | Yes (cpu, count) | Yes (cpu, count) |
| Struct parsing | Manual (ctypes) | Built-in via StructParser |
| Page count config | Yes (power of 2) | Yes (power of 2) |
| Poll with timeout | Yes | Yes |
| Non-blocking consume | Yes | Yes |
| Context manager | Yes | No |

**tinybpf:**
```python
def sample_cb(cpu: int, data: bytes) -> None:
    print(f"CPU {cpu}: {len(data)} bytes")

def lost_cb(cpu: int, count: int) -> None:
    print(f"Lost {count} events on CPU {cpu}")

with BpfPerfBuffer(obj.map("events"), sample_cb, lost_cb) as pb:
    pb.poll(timeout_ms=1000)
```

**pylibbpf:**
```python
def callback(cpu, data):
    print(f"CPU {cpu}: {len(data)} bytes")

def lost_callback(cpu, count):
    print(f"Lost {count} events on CPU {cpu}")

perf = PerfEventArray(obj["events"], 8, callback, lost_callback)
perf.poll(1000)
```

---

## 5. Error Handling

| Aspect | tinybpf | pylibbpf |
|--------|---------|----------|
| Exception class | `BpfError` | `BpfException` |
| errno access | `error.errno` | No |
| libbpf errors | Converted via `libbpf_strerror()` | Converted |
| Validation | Extensive pre-checks | Basic checks |
| Use-after-close | Detected and raised | Not mentioned |

**tinybpf** uses libbpf's `-errno` return convention and provides the errno value for programmatic handling.

---

## 6. Type System & Struct Support

### tinybpf
- Generic types: `BpfMap[KT, VT]` where types can be `bytes`, `int`, or `ctypes.Structure`
- Manual struct definition using standard ctypes
- Strict mypy type checking throughout

```python
class Event(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32), ("comm", ctypes.c_char * 16)]

# Type hints help IDE and type checkers
map: BpfMap[int, Event] = obj.map("events")
```

### pylibbpf
- StructParser class for deserializing map values
- Integration with PythonBPF's LLVM IR struct definitions
- `ir_to_ctypes` converter for automatic ctypes generation

```python
from pylibbpf import StructParser

structs = {"Event": Event}  # ctypes structures
obj = BpfObject("prog.o", structs)
map = obj["events"]
map.set_value_struct("Event")
```

---

## 7. Async & Concurrency

| Feature | tinybpf | pylibbpf |
|---------|---------|----------|
| asyncio integration | Yes | No |
| `async for` iteration | Yes (ring buffer) | No |
| `poll_async()` | Yes | No |
| GIL management | Automatic (ctypes) | Manual in C++ |
| Thread safety | Yes (Python GIL) | Yes (explicit) |

**tinybpf async example:**
```python
import asyncio
from tinybpf import load, BpfRingBuffer

async def main():
    with load("prog.bpf.o") as obj:
        rb = BpfRingBuffer(obj.map("events"))
        async for event in rb:
            await process(event)

asyncio.run(main())
```

---

## 8. Resource Management

| Feature | tinybpf | pylibbpf |
|---------|---------|----------|
| Context managers | `BpfObject`, `BpfLink`, `BpfRingBuffer`, `BpfPerfBuffer` | None |
| Automatic cleanup | Yes (on `__exit__`) | Manual |
| Link detachment | Auto on close | Manual `detach()` |
| Object closure | Explicit `close()` or context manager | GC-dependent |

**tinybpf** provides comprehensive RAII-style resource management:
```python
with load("prog.bpf.o") as obj:
    with obj.program("my_prog").attach_kprobe("func") as link:
        # link auto-detaches, object auto-closes
        pass
```

---

## 9. Dependencies

### tinybpf

**Runtime:**
- Python 3.10+
- libelf (system, typically pre-installed)
- Linux kernel 5.8+ (for CO-RE)

**Build-time (development only):**
- setuptools 61.0+
- Docker (for eBPF program compilation)

### pylibbpf

**Runtime:**
- Python 3.12+ (for wheels) or 3.8+ (source build)
- libelf (system)
- llvmlite >= 0.40.0 (optional, for PythonBPF)

**Pre-built wheels (x86_64 only):**
- No build-time dependencies
- `pip install pylibbpf` just works

**Build from source (ARM64 or Python <3.12):**
- CMake >= 4.0
- C++20 compiler (GCC/Clang)
- Python development headers
- ninja (optional but recommended)
- libelf-dev, zlib-dev (system packages)
- pybind11 and libbpf fetched as git submodules

---

## 10. Installation

### tinybpf
```bash
pip install tinybpf
```
Pre-built wheels available; no compilation needed.

### pylibbpf

**Via PyPI (x86_64, Python 3.12+ only):**
```bash
pip install pylibbpf
```
Pre-built wheels available for x86_64 Linux with Python 3.12 or 3.13.

**From source (ARM64 or Python 3.8-3.11):**
```bash
sudo apt install libelf-dev cmake ninja-build  # build dependencies
git clone --recursive https://github.com/pythonbpf/pylibbpf.git
cd pylibbpf
pip install .
```
Requires C++20 toolchain for source builds.

---

## 11. Project Maturity

| Aspect | tinybpf | pylibbpf |
|--------|---------|----------|
| Version | 0.0.1 | 0.0.7 (Alpha) |
| Production ready | Yes | No (explicit warning) |
| Documentation | README + CLAUDE.md + DEVELOPMENT.md | Minimal |
| Test coverage | Comprehensive (pytest + asyncio) | Basic integration test |
| Type hints | Complete (mypy strict) | None |
| Code quality | ruff, mypy, pre-commit | None mentioned |

---

## 12. Unique Features

### tinybpf Only
- **CO-RE (Compile Once, Run Everywhere)** support
- **Ring buffer** with full async/iterator support
- **Context managers** for automatic cleanup
- **Generic type hints** (`BpfMap[KT, VT]`)
- **Update flags** (BPF_ANY, BPF_NOEXIST, BPF_EXIST)
- **Async iteration** for event processing
- **Zero-copy memoryview** mode for ring buffers
- **Multi-map ring buffer** support
- **libbpf_version()** API

### pylibbpf Only
- **PythonBPF integration** (LLVM IR struct conversion)
- **StructParser** class for automatic value deserialization
- **Built-in struct mode** in PerfEventArray
- **Python 3.8 support** (vs 3.10+ for tinybpf)
- **Fluent wrapper API** (`PerfEventArrayHelper`)

---

## 13. Use Cases

### Choose tinybpf when:
- You need **pre-built wheels** without compilation
- **Async/await** patterns are important
- **Ring buffers** are required
- **CO-RE programs** are the target
- **Production deployment** is the goal
- Strong **type safety** is desired

### Choose pylibbpf when:
- **PythonBPF** integration is needed
- **Python 3.8/3.9** support is required
- **Built-in struct parsing** for perf buffers is desired
- You're comfortable building from source
- Performance of C++ bindings is critical

---

## 14. API Reference Summary

### tinybpf Core Classes
```python
# Loading
obj = tinybpf.load("prog.bpf.o")  # or use context manager

# Programs
prog = obj.program("name")        # BpfProgram
link = prog.attach()              # BpfLink
link = prog.attach_kprobe("fn")   # BpfLink

# Maps
map = obj.map("name")             # BpfMap[KT, VT]
value = map[key]                  # lookup
map[key] = value                  # update
del map[key]                      # delete

# Buffers
rb = BpfRingBuffer(map, callback) # Ring buffer
pb = BpfPerfBuffer(map, cb, lost) # Perf buffer
```

### pylibbpf Core Classes
```python
# Loading
obj = pylibbpf.BpfObject("prog.o", structs={})
obj.load()

# Programs
prog = obj.get_program("name")    # BpfProgram
prog.attach()
obj.attach_all()                  # dict of attachments

# Maps
map = obj.get_map("name")         # BpfMap
map = obj["name"]                 # alternative
value = map[key]                  # lookup
map[key] = value                  # update

# Perf Buffer
perf = PerfEventArray(map, page_cnt, callback)
perf.poll(timeout_ms)
```

---

## 15. Conclusion

**tinybpf** is a more mature, production-ready library with:
- Zero build dependencies (pure Python wheels)
- Comprehensive async support
- Full ring buffer implementation
- Strong type safety
- Automatic resource management

**pylibbpf** is an early-stage project focused on:
- Integration with PythonBPF ecosystem
- C++ performance through pybind11
- Broader Python version support

For most eBPF-from-Python use cases, **tinybpf** offers a more complete and easier-to-deploy solution, while **pylibbpf** may be preferred for tight PythonBPF integration or when C++ binding performance is critical.

---

*Comparison generated on 2026-01-16*
*tinybpf version: 0.0.1 | pylibbpf version: 0.0.7*
