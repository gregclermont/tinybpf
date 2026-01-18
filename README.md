# tinybpf

Minimal Python library for loading and interacting with compiled eBPF programs.

- Pure Python (ctypes bindings to bundled libbpf)
- No build dependencies, no runtime dependencies except libelf
- Dict-like map access, ring buffer streaming, context managers

> [!NOTE]
> **Using an AI assistant?** Give it [llms.txt](https://raw.githubusercontent.com/gregclermont/tinybpf/main/llms.txt) for accurate API help.

## Install

```bash
uv add tinybpf --index https://gregclermont.github.io/tinybpf
```

<details>
<summary>pip</summary>

```bash
pip install tinybpf --extra-index-url https://gregclermont.github.io/tinybpf
```
</details>

Wheels available for `manylinux_2_28_x86_64` and `manylinux_2_28_aarch64`.

## Usage

```python
import tinybpf

with tinybpf.load("program.bpf.o") as obj:
    # Attach a program
    link = obj.program("trace_exec").attach_kprobe("do_execve")

    # Read from a map
    for key, value in obj.maps["events"].items():
        print(key, value)
```

Typed access with `ctypes.Structure`:

```python
import ctypes

class Event(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32), ("comm", ctypes.c_char * 16)]

for key, event in obj.maps["events"].typed(value=Event).items():
    print(f"PID {event.pid}: {event.comm.decode()}")
```

## API

### Loading

- `tinybpf.load(path)` - Load a `.bpf.o` file, returns `BpfObject`
- `tinybpf.open_pinned_map(path)` - Open a pinned map from bpffs
- `tinybpf.init(libbpf_path)` - Use custom libbpf.so (optional, call before other functions)

### BpfObject

- `obj.programs` - Dict-like access to programs by name
- `obj.maps` - Dict-like access to maps by name
- `obj.program(name)` - Get program by name
- Context manager support (`with` statement)

### Type Registration

Register Python types for BTF validation:

- `obj.register_type(btf_name, python_type, validate_field_names=True)` - Register and validate against BTF
- `obj.lookup_type(btf_name)` - Get registered type by BTF name
- `obj.lookup_btf_name(python_type)` - Get BTF name for registered type

See [GUIDE.md](GUIDE.md#btf-anchoring) for BTF anchoring requirements.

### BpfProgram

Section names determine program type and auto-attach behavior:

| Section Pattern | Program Type | Auto-attach |
|----------------|--------------|-------------|
| `kprobe/<func>` | kprobe | Yes, to function |
| `kretprobe/<func>` | kretprobe | Yes, to function |
| `tracepoint/<cat>/<name>` | tracepoint | Yes |
| `raw_tracepoint/<name>` | raw tracepoint | Yes |
| `fentry/<func>` | fentry | Yes (kernel 5.5+) |
| `fexit/<func>` | fexit | Yes (kernel 5.5+) |
| `xdp` | XDP | No, use `attach_xdp()` |
| `tc` | TC classifier | No |
| `socket` | socket filter | No |

Attach methods:
- `attach()` - Auto-attach based on section name
- `attach_kprobe(func_name, retprobe=False)`
- `attach_kretprobe(func_name)`
- `attach_tracepoint(category, name)`
- `attach_raw_tracepoint(name)`
- `attach_uprobe(binary_path, offset=0, pid=-1, retprobe=False)`
- `attach_uretprobe(binary_path, offset=0, pid=-1)`
- `attach_xdp(ifindex)` - Attach XDP to network interface

Properties: `name`, `section`, `type`, `fd`, `info`

### BpfMap

Dict-like interface:
- `map[key]`, `map[key] = value`, `del map[key]`
- `key in map`, `for key in map`
- `map.keys()`, `map.values()`, `map.items()`
- `map.lookup(key)`, `map.update(key, value, flags)`, `map.delete(key)`

Typed access:

```python
# int/float auto-convert when BTF metadata is available
counters = obj.maps["counters"]
value = counters[42]  # int

# Use .typed() for ctypes.Structure
events = obj.maps["events"].typed(value=Event)
event = events[pid]  # Event instance
```

See [GUIDE.md](GUIDE.md#typed-map-access) for config maps and iteration patterns.

Pinning (for maps from `BpfObject`):
- `map.pin(path)` - Pin to bpffs
- `map.unpin(path)` - Remove pin

Keys/values: `bytes`, `int`, or `ctypes.Structure`

Properties: `name`, `type`, `key_size`, `value_size`, `max_entries`, `fd`, `info`

### BpfRingBuffer

Stream events from `BPF_MAP_TYPE_RINGBUF` maps:

```python
rb = BpfRingBuffer(obj.maps["events"], callback=lambda data: print(len(data)))
rb.poll(timeout_ms=1000)
```

- `BpfRingBuffer(map, callback)` - Create with callback receiving `bytes`
- `BpfRingBuffer()` then `rb.add(map)` - Multi-map support
- `rb.poll(timeout_ms)` - Poll for events, invoke callbacks
- `rb.consume()` - Process available events without waiting
- Async support: `await rb.poll_async()`, `async for event in rb`
- Iterator mode: omit callback, use `for data in rb` after `poll()`
- Context manager support

Typed events with auto-conversion:

```python
class Event(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32), ("comm", ctypes.c_char * 16)]

def handle(event: Event):
    print(event.pid)

rb = BpfRingBuffer(obj.maps["events"], handle, event_type=Event)
```

See [GUIDE.md](GUIDE.md#event-struct-design) for struct layout patterns and multiple event types.

### BpfPerfBuffer

Stream events from `BPF_MAP_TYPE_PERF_EVENT_ARRAY` maps:

```python
pb = BpfPerfBuffer(obj.maps["events"], sample_callback=lambda cpu, data: print(cpu, len(data)))
pb.poll(timeout_ms=1000)
```

- `BpfPerfBuffer(map, sample_callback, lost_callback=None)`
- `pb.poll(timeout_ms)` - Poll for events
- `pb.consume()` - Process available events without waiting
- Context manager support

Typed events with auto-conversion:

```python
class Event(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32), ("comm", ctypes.c_char * 16)]

def handle(cpu: int, event: Event) -> None:
    print(cpu, event.pid)

pb = BpfPerfBuffer(obj.maps["events"], handle, event_type=Event)
```

### BpfLink

- `link.destroy()` - Detach the program
- `link.fd` - File descriptor
- Context manager support

### Other

- `tinybpf.version()` - Package version
- `tinybpf.libbpf_version()` - Bundled libbpf version
- `BpfError` - Exception with `errno` and `libbpf_log` (diagnostic output on load failures)
- `BtfValidationError` - Exception for BTF type mismatches

See [GUIDE.md](GUIDE.md#debugging) for debugging load failures and interpreting errors.

## Requirements

- Linux with kernel 5.8+ (for ring buffers; basic features work on older kernels)
- libelf (typically pre-installed)
- Root or `CAP_BPF` capability

## Building on tinybpf

For detailed guidance on CO-RE compatibility, event struct design, and debugging, see [GUIDE.md](GUIDE.md).

### Compiling eBPF programs

Use the `ghcr.io/gregclermont/tinybpf-compile` Docker image:

```bash
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c
```

Output files are written alongside sources. The image includes libbpf headers and `vmlinux.h` (kernel 6.18) for CO-RE support. See [GUIDE.md](GUIDE.md#custom-vmlinuxh) to use a custom vmlinux.h for older kernels.

