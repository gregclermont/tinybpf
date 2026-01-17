# Multiple Event Types Example

Demonstrates handling different event types through a single ring buffer using a discriminator field.

The BPF program emits two event types:
- `EXEC` events when a process calls execve
- `EXIT` events when a process exits

Both share a common header with the discriminator at a fixed offset, allowing Python to dispatch to the correct struct.

## Run

```bash
make compile  # from repo root
sudo $(which uv) run main.py
```

## Key Pattern

```c
// C: All event types share the same header layout
struct exec_event {
    __u64 timestamp;
    __u8 event_type;  // Discriminator at offset 8
    __u8 _pad[3];
    // ... type-specific fields
};
```

```python
# Python: Read discriminator, then convert to correct type
event_type = data[8]
if event_type == EVENT_EXEC:
    event = ExecEvent.from_buffer_copy(data)
```

## See Also

- [GUIDE.md: Multiple Event Types](../../GUIDE.md#multiple-event-types)
