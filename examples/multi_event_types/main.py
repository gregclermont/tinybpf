#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "tinybpf>=0.0.1",
# ]
#
# [[tool.uv.index]]
# url = "https://gregclermont.github.io/tinybpf"
# ///
"""Handle multiple event types through one ring buffer using discriminator."""

import ctypes
from pathlib import Path
from typing import Callable

import tinybpf

EVENT_EXEC = 1
EVENT_EXIT = 2


# -----------------------------------------------------------------------------
# Event struct definitions (must match BPF side)
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# EventDispatcher - reusable pattern for polymorphic ring buffer events
# -----------------------------------------------------------------------------


class EventDispatcher:
    """Dispatch ring buffer events to handlers based on a discriminator field.

    Copy this class into your project and adapt as needed.

    Usage:
        dispatcher = EventDispatcher(
            discriminator_offset=8,  # byte offset of type field
            discriminator_size=1,    # 1=u8, 2=u16, 4=u32
        )
        dispatcher.register(EVENT_EXEC, ExecEvent, handle_exec)
        dispatcher.register(EVENT_EXIT, ExitEvent, handle_exit)

        rb = tinybpf.BpfRingBuffer(map, dispatcher)
    """

    def __init__(self, discriminator_offset: int, discriminator_size: int = 1):
        self.offset = discriminator_offset
        self.size = discriminator_size
        self.handlers: dict[int, tuple[type[ctypes.Structure], Callable]] = {}

    def register(
        self,
        type_value: int,
        struct_type: type[ctypes.Structure],
        handler: Callable,
    ) -> "EventDispatcher":
        """Register a handler for an event type. Returns self for chaining."""
        self.handlers[type_value] = (struct_type, handler)
        return self

    def __call__(self, data: bytes) -> int:
        """Ring buffer callback - dispatches to registered handler."""
        if len(data) < self.offset + self.size:
            return 0

        type_value = int.from_bytes(
            data[self.offset : self.offset + self.size], byteorder="little"
        )

        entry = self.handlers.get(type_value)
        if entry is None:
            return 0

        struct_type, handler = entry
        if len(data) < ctypes.sizeof(struct_type):
            return 0

        event = struct_type.from_buffer_copy(data)
        handler(event)
        return 0


# -----------------------------------------------------------------------------
# Event handlers
# -----------------------------------------------------------------------------


def handle_exec(event: ExecEvent) -> None:
    ts_ms = event.timestamp / 1_000_000
    print(f"{ts_ms:>12.3f} EXEC  pid={event.pid:<6} {event.comm.decode()}")


def handle_exit(event: ExitEvent) -> None:
    ts_ms = event.timestamp / 1_000_000
    print(f"{ts_ms:>12.3f} EXIT  pid={event.pid:<6} code={event.exit_code}")


def main() -> None:
    bpf_obj = Path(__file__).parent / "events.bpf.o"

    print(f"Loading {bpf_obj}")
    with tinybpf.load(bpf_obj) as obj:
        # Attach both programs
        link_exec = obj.programs["trace_exec"].attach()
        link_exit = obj.programs["trace_exit"].attach()
        print("Attached to sys_enter_execve and sched_process_exit. Press Ctrl+C to exit.\n")

        # Set up dispatcher for polymorphic events
        # Discriminator is at offset 8 (after timestamp), size 1 byte (u8)
        dispatcher = EventDispatcher(discriminator_offset=8, discriminator_size=1)
        dispatcher.register(EVENT_EXEC, ExecEvent, handle_exec)
        dispatcher.register(EVENT_EXIT, ExitEvent, handle_exit)

        rb = tinybpf.BpfRingBuffer(obj.maps["events"], dispatcher)

        print(f"{'TIME (ms)':>12} EVENT {'PID':<6} INFO")
        print("-" * 50)
        try:
            while True:
                rb.poll(timeout_ms=100)
        except KeyboardInterrupt:
            print("\nDetaching...")
            link_exec.destroy()
            link_exit.destroy()


if __name__ == "__main__":
    main()
