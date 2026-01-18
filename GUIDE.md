# BPF Development Guide

This guide covers patterns and best practices for writing BPF programs that work with tinybpf. For API reference, see [README.md](README.md).

## Compiling BPF Programs

Use the `ghcr.io/gregclermont/tinybpf-compile` Docker image to compile `.bpf.c` files:

```bash
# Compile a single file
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile program.bpf.c

# Compile multiple files
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c

# Output to specific directory
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile -o build/ src/*.bpf.c
```

The image bundles libbpf headers and `vmlinux.h` (kernel 6.18) for CO-RE support. Output `.bpf.o` files are written alongside sources (or to the specified output directory).

### Custom vmlinux.h

For targeting older kernels, provide your own vmlinux.h via the `VMLINUX` env var:

```bash
docker run --rm -v $(pwd):/src -v /path/to/vmlinux.h:/vmlinux.h \
  -e VMLINUX=/vmlinux.h ghcr.io/gregclermont/tinybpf-compile program.bpf.c
```

Generate vmlinux.h from a target system:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## CO-RE Compatibility

### What is CO-RE?

CO-RE (Compile Once, Run Everywhere) allows BPF programs compiled against one kernel's type definitions to run on different kernels. At load time, libbpf relocates struct field offsets based on the target kernel's BTF metadata.

### The vmlinux.h Source

The Docker image bundles `vmlinux.h` from the official [libbpf/vmlinux.h](https://github.com/libbpf/vmlinux.h) repository (kernel 6.18). This is the same approach used by bcc/libbpf-tools and other production BPF tooling.

Supported architectures: x86_64, aarch64, arm, riscv64, s390x, ppc64le, loongarch64.

### When CO-RE Relocations Fail

Relocation fails when your BPF program accesses a struct field that either:
- Doesn't exist in the target kernel
- Has a fundamentally different layout (e.g., inline array vs dynamic pointer)

Example error:
```
libbpf: prog 'trace_fork': relo #3: failed to resolve CO-RE relocation <byte_off> [42] struct trace_event_raw_sched_process_fork.comm
```

When loading fails, `BpfError` includes diagnostic output:

```python
try:
    obj = tinybpf.load("program.bpf.o")
except tinybpf.BpfError as e:
    if e.libbpf_log:
        print("libbpf diagnostics:")
        print(e.libbpf_log)
```

### Writing Portable BPF Code

**1. Use kernel helpers instead of direct struct access:**

```c
// Fragile: tracepoint struct layouts vary between kernels
char *comm = ctx->comm;  // May fail on some kernels

// Portable: kernel helper works everywhere
char comm[TASK_COMM_LEN];
bpf_get_current_comm(&comm, sizeof(comm));
```

**2. Use `bpf_core_field_exists()` for conditional access:**

```c
if (bpf_core_field_exists(ctx->comm)) {
    // Safe to access ctx->comm on this kernel
} else {
    // Fallback for kernels without this field
}
```

**3. Avoid tracepoint event structs when possible:**

Tracepoint event structs (like `trace_event_raw_sched_process_*`) are particularly prone to layout changes. Consider using kprobes/fentry with kernel helpers instead.

## Typed Map Access

### Config Maps

A common pattern is using a single-entry array map to pass configuration from userspace to BPF:

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

### Iterating Typed Maps

For maps with structured keys and values:

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

## Event Struct Design

When sending events from BPF to userspace via ring buffers or perf buffers, careful struct design ensures reliable data transfer.

### Basic Struct Layout

```c
// BPF side (C)
struct event {
    __u32 pid;
    __u32 tid;
    char comm[16];
};
```

```python
# Python side
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]
```

Key rules:
- Python struct must exactly match C layout including padding
- Use explicit sizes (`c_uint32`, not `c_int`)
- Use `ctypes.sizeof(Event)` to verify sizes match

### BTF Anchoring

Event structs used only locally in BPF are optimized out of BTF. To make a struct available for BTF validation, anchor it:

```c
// Add a global variable (recommended)
struct event _event_btf __attribute__((unused));
```

Then validate in Python:

```python
obj.register_type("event", Event)  # Validates against BTF
rb = BpfRingBuffer(obj.maps["events"], handle, event_type=Event)
```

### Multiple Event Types

When sending different event types through one ring buffer, use a discriminator field at a consistent offset:

```c
// All event types share the same header layout
struct exec_event {
    __u64 timestamp;
    __u8 event_type;      // Discriminator at offset 8
    __u8 _pad[3];
    __u32 pid;
    char comm[16];
};

struct exit_event {
    __u64 timestamp;
    __u8 event_type;      // Same offset
    __u8 _pad[3];
    __u32 pid;
    __s32 exit_code;
};

#define EVENT_EXEC 1
#define EVENT_EXIT 2
```

```python
EVENT_EXEC, EVENT_EXIT = 1, 2

class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 3),
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]

class ExitEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 3),
        ("pid", ctypes.c_uint32),
        ("exit_code", ctypes.c_int32),
    ]

def handle(data: bytes):
    event_type = data[8]  # Read discriminator at known offset
    if event_type == EVENT_EXEC:
        event = ExecEvent.from_buffer_copy(data)
    elif event_type == EVENT_EXIT:
        event = ExitEvent.from_buffer_copy(data)

rb = BpfRingBuffer(obj.maps["events"], handle)
```

Key points:
- Put discriminator at the same offset in all C structs
- Use explicit `_pad` fields to control alignment
- Validate `len(data)` before `from_buffer_copy()` to catch truncated events

### Alternative: Separate Buffers

If you don't need strict ordering across event types, use separate ring buffers:

```python
rb = BpfRingBuffer()
rb.add(obj.maps["exec_events"], handle_exec, event_type=ExecEvent)
rb.add(obj.maps["exit_events"], handle_exit, event_type=ExitEvent)
```

This avoids manual type discrimination and gives you typed callbacks.

## Debugging

### Reading libbpf Diagnostics

When `tinybpf.load()` fails, the exception includes libbpf's diagnostic output:

```python
try:
    obj = tinybpf.load("program.bpf.o")
except tinybpf.BpfError as e:
    print(f"Error: {e}")
    if e.libbpf_log:
        print("\nlibbpf output:")
        print(e.libbpf_log)
```

Common messages in `libbpf_log`:
- `failed to resolve CO-RE relocation` - struct field doesn't exist on target kernel
- `invalid func unknown#...` - CO-RE relocation was "poisoned" due to missing field
- `R1 type=... expected=...` - verifier type mismatch

### Inspecting BTF

Use `bpftool` to examine BTF metadata in compiled objects:

```bash
# Dump all BTF types
bpftool btf dump file program.bpf.o

# Search for a specific struct
bpftool btf dump file program.bpf.o | grep -A 10 "'event'"
```

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Size mismatch` in BTF validation | Python struct size differs from C | Check padding, use explicit `_pad` fields |
| `No such file or directory` on attach | Kernel function doesn't exist | Check function name spelling, kernel version |
| CO-RE relocation failed | Struct field missing on target kernel | Use kernel helpers or `bpf_core_field_exists()` |
| Events have garbage data | Struct layout mismatch | Verify C and Python structs match exactly |

## Development Setup

### Running with Root

BPF operations require root privileges. When using uv:

```bash
# sudo resets PATH, so uv won't be found. Resolve the path first:
sudo $(which uv) run python my_bpf_script.py
```

### CI Workflow

Example GitHub Actions workflow to compile BPF programs and run tests:

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

### Local Development on macOS

Since eBPF requires Linux, use [Lima](https://lima-vm.io/) to run a Linux VM:

```bash
# Create and start an Ubuntu VM
limactl create --name=ebpf template:ubuntu-24.04
limactl start ebpf

# Run commands in the VM
limactl shell ebpf -- sudo pytest /path/to/your/tests -v
```

You'll need to configure mounts for your project directory.

## See Also

- [README.md](README.md) - API reference
- [examples/](examples/) - Runnable example programs
