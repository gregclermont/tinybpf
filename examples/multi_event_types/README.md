# Multiple Event Types Example

Demonstrates handling different event types through a single ring buffer using a discriminator field and a reusable `EventDispatcher` pattern.

The BPF program emits two event types:
- `EXEC` events when a process calls execve
- `EXIT` events when a process exits

Both share a common header with the discriminator at a fixed offset, allowing Python to dispatch to the correct struct and handler.

## Run

```bash
tinybpf docker-compile events.bpf.c
tinybpf run-elevated main.py
```

## Key Pattern: Shared Header with Discriminator

All event types must share the same header layout so the discriminator is at a fixed offset:

```c
// C: Both event types have identical header layout
struct exec_event {
    __u64 timestamp;
    __u8 event_type;  // Discriminator at offset 8
    __u8 _pad[3];
    // ... type-specific fields
};

struct exit_event {
    __u64 timestamp;
    __u8 event_type;  // Same offset!
    __u8 _pad[3];
    // ... type-specific fields
};
```

## EventDispatcher Pattern

The `EventDispatcher` class (defined in `main.py`) provides a reusable abstraction for this pattern. Copy it into your project and adapt as needed:

```python
# Set up dispatcher - discriminator at offset 8, size 1 byte (u8)
dispatcher = EventDispatcher(discriminator_offset=8, discriminator_size=1)
dispatcher.register(EVENT_EXEC, ExecEvent, handle_exec)
dispatcher.register(EVENT_EXIT, ExitEvent, handle_exit)

# Use as ring buffer callback
rb = tinybpf.BpfRingBuffer(map, dispatcher)
```

The dispatcher:
1. Reads the discriminator value from the raw bytes
2. Looks up the registered struct type and handler
3. Validates the data length against struct size
4. Converts bytes to the correct ctypes.Structure
5. Calls your handler with the typed event

### Manual Alternative

For simple cases, manual dispatch may be clearer:

```python
def handle_event(data: bytes) -> int:
    event_type = data[8]
    if event_type == EVENT_EXEC:
        event = ExecEvent.from_buffer_copy(data)
        # handle exec...
    elif event_type == EVENT_EXIT:
        event = ExitEvent.from_buffer_copy(data)
        # handle exit...
    return 0
```

## See Also

- [GUIDE.md: Multiple Event Types](../../GUIDE.md#multiple-event-types)
