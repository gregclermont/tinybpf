# tinybpf

Minimal Python library for loading and interacting with compiled eBPF programs.

- Pure Python (ctypes bindings to bundled libbpf)
- No build dependencies, no runtime dependencies except libelf
- Dict-like map access, ring buffer streaming, context managers

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

Register Python types for BTF validation and automatic type inference:

```python
class Event(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32), ("comm", ctypes.c_char * 16)]

# Register type - validates against BTF metadata
obj.register_type("event", Event)

# Registered types are auto-validated in ring/perf buffers
rb = BpfRingBuffer(obj.maps["events"], event_type=Event)  # auto-validates
```

- `obj.register_type(btf_name, python_type, validate_field_names=True)` - Register and validate a Python type against BTF struct
- `obj.lookup_type(btf_name)` - Get registered Python type by BTF name (or None)
- `obj.lookup_btf_name(python_type)` - Get BTF name for registered type (or None)

Use `validate_field_names=False` to allow renamed fields in Python while keeping size/offset validation.

Note: Event structs used only locally in BPF are optimized out of BTF. Add a global anchor:
```c
struct event _event_btf __attribute__((unused));
```

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

For program types without auto-attach info in the section name (like `xdp`), use function names to distinguish multiple programs and attach explicitly:

```c
SEC("xdp") int xdp_pass(struct xdp_md *ctx) { return XDP_PASS; }
SEC("xdp") int xdp_drop(struct xdp_md *ctx) { return XDP_DROP; }
```

```python
obj.programs["xdp_pass"].attach_xdp(ifindex)
```

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
# int/float keys and values auto-convert when BTF metadata is available
counters = obj.maps["counters"]
value = counters[42]  # int (auto-converted via BTF)

# Use .typed() for ctypes.Structure or explicit validation
events = obj.maps["events"].typed(value=Event)
event = events[pid]  # Event instance
```

Config maps with structs:

```python
class Config(ctypes.Structure):
    _fields_ = [
        ("target_pid", ctypes.c_uint32),
        ("enabled", ctypes.c_uint8),
    ]

# Write config to single-entry array map at index 0
config_map = obj.maps["config"].typed(key=ctypes.c_uint32, value=Config)
cfg = Config(target_pid=1234, enabled=1)
config_map[0] = cfg

# Read it back
current = config_map[0]
print(f"Filtering PID: {current.target_pid}")
```

Iterating typed maps:

```python
class PortStats(ctypes.Structure):
    _fields_ = [
        ("connections", ctypes.c_uint64),
        ("bytes_sent", ctypes.c_uint64),
    ]

stats_map = obj.maps["port_stats"].typed(key=ctypes.c_uint16, value=PortStats)
for port, stats in stats_map.items():
    print(f"Port {port}: {stats.connections} connections")
```

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

# Without event_type: callback receives bytes, requires manual conversion
def handle(data: bytes):
    event = Event.from_buffer_copy(data)

# With event_type: callback receives Event directly (recommended)
def handle(event: Event):
    print(event.pid)

rb = BpfRingBuffer(obj.maps["events"], handle, event_type=Event)
```

Multiple event types through one buffer:

```python
# C structs must have discriminator at consistent offset across all event types:
#   struct exec_event { __u64 ts; __u8 event_type; __u8 _pad[3]; __u32 pid; ... };
#   struct exit_event { __u64 ts; __u8 event_type; __u8 _pad[3]; __u32 pid; ... };

EVENT_EXEC, EVENT_EXIT = 1, 2

class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 3),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]

class ExitEvent(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 3),
        ("pid", ctypes.c_uint32),
        ("exit_code", ctypes.c_int32),
    ]

def handle(data: bytes):
    event_type = data[8]  # Read discriminator at known offset
    if event_type == EVENT_EXEC and len(data) >= ctypes.sizeof(ExecEvent):
        event = ExecEvent.from_buffer_copy(data)
    elif event_type == EVENT_EXIT and len(data) >= ctypes.sizeof(ExitEvent):
        event = ExitEvent.from_buffer_copy(data)

rb = BpfRingBuffer(obj.maps["events"], handle)  # No event_type; handle bytes manually
```

Key points:
- Put discriminator field (`event_type`) at same offset in all C structs
- Use explicit `_pad` fields to control alignment
- Python ctypes struct must exactly match C layout including padding
- Validate `len(data)` before `from_buffer_copy()` to avoid reading garbage

**Alternative:** If you don't need strict ordering across event types, use separate ring buffers with multi-map and typed callbacks:

```python
rb = BpfRingBuffer()
rb.add(obj.maps["exec_events"], handle_exec, event_type=ExecEvent)
rb.add(obj.maps["exit_events"], handle_exit, event_type=ExitEvent)
```

This avoids manual type discrimination entirely.

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
- `BpfError` - Exception type with `errno` attribute
- `BtfValidationError` - Exception for BTF type mismatches

## Requirements

- Linux with kernel 5.8+ (for ring buffers; basic features work on older kernels)
- libelf (typically pre-installed)
- Root or `CAP_BPF` capability

## Building on tinybpf

### Compiling eBPF programs

Use the `ghcr.io/gregclermont/tinybpf-compile` Docker image to compile `.bpf.c` files:

```bash
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c
```

Output files are written alongside the sources. Use `-o build/` to specify an output directory.

The image includes libbpf headers and `vmlinux.h` for x86_64 and aarch64. It auto-detects the target architecture.

### CI workflow

Example GitHub Actions workflow to compile and test:

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Compile eBPF programs
        run: |
          docker run --rm -v ${{ github.workspace }}:/src \
            ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c -o build/

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install tinybpf --extra-index-url https://gregclermont.github.io/tinybpf
          pip install pytest

      - name: Run tests
        run: sudo pytest tests/ -v
```

### Local development on macOS

Since eBPF requires Linux, use [Lima](https://lima-vm.io/) to run a Linux VM:

```bash
# Create and start an Ubuntu VM
limactl create --name=ebpf template:ubuntu-24.04
limactl start ebpf

# Run commands in the VM
limactl shell ebpf -- sudo pytest /path/to/your/tests -v
```

You'll need to configure mounts for your project directory. See this project's [Makefile](Makefile) for a complete setup with `lima-create`, `lima-shell`, and automatic mount configuration.

## For AI Assistants

See [llms.txt](./llms.txt) for a machine-readable API reference.
