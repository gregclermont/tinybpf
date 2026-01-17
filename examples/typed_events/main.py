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
"""Demonstrate typed events with automatic struct conversion."""

import ctypes
import signal
from pathlib import Path

import tinybpf


class ProcessEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]


def handle_event(event: ProcessEvent) -> int:
    """Callback receives ProcessEvent directly - no from_buffer_copy needed."""
    ts_ms = event.timestamp / 1_000_000
    print(
        f"{ts_ms:>12.3f} pid={event.pid:<6} tgid={event.tgid:<6} "
        f"uid={event.uid:<5} gid={event.gid:<5} {event.comm.decode()}"
    )
    return 0


def main() -> None:
    bpf_obj = Path(__file__).parent / "process_events.bpf.o"

    print(f"Loading {bpf_obj}")
    with tinybpf.load(bpf_obj) as obj:
        # Register type for BTF validation (optional but recommended)
        obj.register_type("process_event", ProcessEvent)
        print(f"ProcessEvent validated against BTF (size={ctypes.sizeof(ProcessEvent)})")

        # Attach to tracepoint
        link = obj.programs["trace_execve"].attach()
        print("Attached to sys_enter_execve. Press Ctrl+C to exit.\n")

        # Ring buffer with event_type - callback receives ProcessEvent directly
        rb = tinybpf.BpfRingBuffer(
            obj.maps["events"], handle_event, event_type=ProcessEvent
        )

        running = True

        def stop(sig, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, stop)

        print(f"{'TIME (ms)':>12} {'PID':<6} {'TGID':<6} {'UID':<5} {'GID':<5} COMM")
        print("-" * 60)
        while running:
            rb.poll(timeout_ms=100)

        print("\nDetaching...")
        link.destroy()


if __name__ == "__main__":
    main()
