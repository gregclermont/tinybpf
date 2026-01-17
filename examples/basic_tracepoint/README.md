# Basic Tracepoint Example

Traces process execution using a tracepoint on `sys_enter_execve`. Demonstrates the basic tinybpf workflow:

1. Load a compiled BPF object
2. Attach a program to a tracepoint
3. Poll a ring buffer for events

## Run

```bash
make compile  # from repo root
sudo $(which uv) run main.py
```

Then run commands in another terminal to see output.

## See Also

- [GUIDE.md: Compiling BPF Programs](../../GUIDE.md#compiling-bpf-programs)
- [README.md: BpfRingBuffer](../../README.md#bpfringbuffer)
