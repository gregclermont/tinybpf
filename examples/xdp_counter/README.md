# XDP Counter Example

Counts packets using XDP (eXpress Data Path) with a per-CPU array map for lock-free updates.

XDP programs run at the earliest point in the network stack, before the kernel allocates socket buffers, making them extremely fast.

## Run

```bash
tinybpf docker-compile counter.bpf.c
tinybpf run-elevated main.py lo  # or eth0, etc.
```

The script attaches to the specified interface and prints packet counts every second.

## Key Concepts

- **XDP programs** don't auto-attach; use `attach_xdp(ifindex)`
- **Per-CPU maps** allow lock-free updates from each CPU
- **XDP return values**: `XDP_PASS` continues normal processing, `XDP_DROP` drops the packet

## See Also

- [README.md: BpfProgram attach methods](../../README.md#bpfprogram)
