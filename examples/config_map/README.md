# Config Map Example

Demonstrates passing configuration from userspace to BPF using a single-entry array map.

The BPF program filters events based on a target PID set from Python. You can update the filter at runtime without reloading.

## Run

```bash
tinybpf docker-compile filter.bpf.c
sudo $(which uv) run main.py
```

The script will:
1. Start with no filter (all PIDs)
2. After 5 seconds, filter to only the current shell's PID
3. After 5 more seconds, disable filtering again

## Key Pattern

```python
# Python: Write config struct to map index 0
config_map = obj.maps["config"].typed(key=ctypes.c_uint32, value=Config)
config_map[0] = Config(target_pid=1234, enabled=1)
```

```c
// BPF: Read config and filter
struct config *cfg = bpf_map_lookup_elem(&config, &zero);
if (cfg && cfg->enabled && cfg->target_pid != pid)
    return 0;  // Skip this event
```

## See Also

- [GUIDE.md: Config Maps](../../GUIDE.md#config-maps)
