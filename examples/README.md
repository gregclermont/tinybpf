# Examples

Runnable examples demonstrating tinybpf patterns. Each example includes:
- BPF program (`.bpf.c`)
- Python script (`main.py`) with inline dependencies (PEP 723)
- Brief README explaining what it demonstrates

## Running Examples

```bash
# Compile all examples
make compile

# Run an example (requires root)
cd examples/basic_tracepoint
sudo $(which uv) run main.py
```

**Why `$(which uv)`?** BPF requires root, but `sudo` resets PATH and won't find `uv`. The subshell resolves the full path first.

Each script declares its dependencies inline, so `uv run` installs tinybpf automatically on first run.

## Examples

| Example | Description | GUIDE.md Section |
|---------|-------------|------------------|
| [basic_tracepoint](basic_tracepoint/) | Trace process execution with tracepoint and ring buffer | [Compiling BPF Programs](../GUIDE.md#compiling-bpf-programs) |
| [typed_events](typed_events/) | Use `event_type` for automatic struct conversion | [Event Struct Design](../GUIDE.md#event-struct-design) |
| [multi_event_types](multi_event_types/) | Handle multiple event types with discriminator field | [Multiple Event Types](../GUIDE.md#multiple-event-types) |
| [config_map](config_map/) | Pass configuration from userspace to BPF | [Config Maps](../GUIDE.md#config-maps) |
| [xdp_counter](xdp_counter/) | Count packets with XDP and per-CPU maps | - |

## Prerequisites

- Linux with kernel 5.8+
- Root or CAP_BPF capability
- [uv](https://docs.astral.sh/uv/) installed
