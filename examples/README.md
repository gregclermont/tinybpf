# tinybpf Examples

This directory contains example programs demonstrating tinybpf features and eBPF capabilities.

## Examples

### 1. Process Tracker (`process_tracker.py`)

A comprehensive process monitoring tool that tracks:
- Process execution (execve syscall)
- Process creation (fork)
- Process termination (exit)
- Process lifetime duration
- Command-line arguments

**Features demonstrated:**
- Ring buffers for event streaming
- Multiple tracepoint programs
- Per-CPU array maps for statistics
- Hash maps for tracking state (process start times)
- BTF type registration and validation
- Filtering by command name

**Usage:**
```bash
sudo python3 process_tracker.py
sudo python3 process_tracker.py --filter python  # Filter by command name
sudo python3 process_tracker.py --no-forks --no-exits  # Only show exec events
sudo python3 process_tracker.py --duration 60  # Run for 60 seconds
```

### 2. Network Connection Tracker (`network_tracker.py`)

Monitors TCP connections including:
- Outgoing connection attempts (connect)
- Incoming connection accepts
- Connection closures
- Per-port statistics

**Features demonstrated:**
- kprobe and kretprobe attachments
- CO-RE (Compile Once, Run Everywhere) with BPF_CORE_READ
- IP address parsing and formatting
- Configuration via BPF hash maps
- LRU hash maps for connection tracking
- Socket structure field access

**Usage:**
```bash
sudo python3 network_tracker.py
sudo python3 network_tracker.py --pid 1234  # Filter by PID
sudo python3 network_tracker.py --port 443  # Filter by port
sudo python3 network_tracker.py --no-closes  # Don't show close events
```

### 3. XDP Packet Filter (`xdp_filter.py`)

A packet filtering firewall demonstrating XDP:
- IP blocklist
- Per-source IP rate limiting
- Protocol-level statistics
- Drop event logging

**Features demonstrated:**
- XDP program attachment to network interfaces
- Packet header parsing (Ethernet, IP, TCP/UDP)
- Multiple XDP programs in one object file
- Per-CPU arrays for high-performance counters
- LRU hash maps for rate limiting state
- Ring buffer for drop notifications
- Runtime configuration via BPF maps

**Usage:**
```bash
# Stats-only mode (no filtering)
sudo python3 xdp_filter.py --interface eth0 --mode stats

# Block specific IPs
sudo python3 xdp_filter.py --interface eth0 --block 1.2.3.4 --block 5.6.7.8

# Rate limiting (1000 packets/sec per source IP)
sudo python3 xdp_filter.py --interface eth0 --rate-limit 1000

# Combined
sudo python3 xdp_filter.py -i eth0 --block 10.0.0.100 --rate-limit 500
```

## Requirements

- Linux kernel 5.8+ (for ring buffers; 4.8+ for basic XDP)
- Root privileges or CAP_BPF capability
- tinybpf library installed
- Compiled BPF object files (`.bpf.o`)

## Compiling BPF Programs

The BPF programs need to be compiled before use. You can compile them using:

### Using Docker (recommended)

```bash
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile examples/bpf/process_tracker.bpf.c
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile examples/bpf/network_tracker.bpf.c
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile examples/bpf/xdp_filter.bpf.c
```

### Using local clang

If you have clang and libbpf-dev installed:

```bash
cd examples/bpf
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf \
    -c process_tracker.bpf.c -o process_tracker.bpf.o
```

## Using System libbpf

If you're running from a development install without bundled libbpf:

```bash
sudo python3 process_tracker.py --libbpf /usr/lib/x86_64-linux-gnu/libbpf.so
```

## File Structure

```
examples/
├── README.md
├── process_tracker.py     # Process monitoring example
├── network_tracker.py     # TCP connection tracking example
├── xdp_filter.py          # XDP packet filter example
└── bpf/
    ├── vmlinux.h          # Minimal kernel types for CO-RE
    ├── process_tracker.bpf.c
    ├── process_tracker.bpf.o
    ├── network_tracker.bpf.c
    ├── network_tracker.bpf.o
    ├── xdp_filter.bpf.c
    └── xdp_filter.bpf.o
```

## Common Issues

### "Function not implemented" error
The BPF syscall is not available. This happens in containers without BPF support
or on kernels without CONFIG_BPF_SYSCALL=y.

### "RLIMIT_MEMLOCK" warning
Run with higher memory limits:
```bash
ulimit -l unlimited
```

### Ring buffer not supported
Ring buffers require kernel 5.8+. Use perf buffers instead for older kernels.

### XDP attachment fails
- Ensure the interface exists and is up
- Some virtual interfaces don't support XDP
- Try using `--mode stats` for a simpler program

## API Patterns Used

### Loading and Attaching Programs

```python
import tinybpf

with tinybpf.load("program.bpf.o") as obj:
    prog = obj.program("my_program")
    link = prog.attach()  # Auto-attach based on section name
    # or: link = prog.attach_kprobe("tcp_connect")
    # or: link = prog.attach_xdp(ifindex)
```

### Ring Buffer Events

```python
def handle_event(data: bytes) -> int:
    event = MyEvent.from_buffer_copy(data)
    print(event.pid)
    return 0  # Continue; return -1 to stop

rb = tinybpf.BpfRingBuffer(obj.maps["events"], callback=handle_event)
rb.poll(timeout_ms=1000)
```

### Map Operations

```python
# Direct access
obj.maps["counters"][key] = value
value = obj.maps["counters"][key]

# Iteration
for key, value in obj.maps["hash_map"].items():
    print(key, value)

# Typed access
typed_map = obj.maps["events"].typed(value=MyStruct)
```

### Type Registration

```python
obj.register_type("event", Event)  # Register for BTF validation
```
