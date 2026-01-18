# Cgroup Egress Counter

Counts outgoing network packets for processes in a cgroup using a `cgroup_skb/egress` BPF program.

## What it demonstrates

- Cgroup BPF program attachment with `attach_cgroup()`
- Finding the current process's cgroup path
- Using an array map as a simple counter

## Files

- `egress_filter.bpf.c` - BPF program that counts egress packets
- `main.py` - Python script that loads and attaches the program

## Run

```bash
make compile  # from repo root
sudo $(which uv) run main.py
```

Generate some network traffic in another terminal to see the counter increase.

## See also

- [GUIDE.md - Cgroup Programs](../../GUIDE.md#cgroup-programs) for more on cgroup attachment patterns
