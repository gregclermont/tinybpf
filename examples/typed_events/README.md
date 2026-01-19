# Typed Events Example

Demonstrates using `event_type` parameter for automatic struct conversion.

**Without `event_type`:** Callback receives `bytes`, you must call `Event.from_buffer_copy(data)`.

**With `event_type`:** Callback receives `Event` directly - cleaner and less error-prone.

This example also shows BTF validation with `register_type()`.

## Run

```bash
tinybpf docker-compile process_events.bpf.c
sudo $(which uv) run main.py
```

## See Also

- [GUIDE.md: Event Struct Design](../../GUIDE.md#event-struct-design)
- [GUIDE.md: BTF Anchoring](../../GUIDE.md#btf-anchoring)
