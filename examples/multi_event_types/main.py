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
import signal
from pathlib import Path

import tinybpf

EVENT_EXEC = 1
EVENT_EXIT = 2


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


def handle_event(data: bytes) -> int:
    """Dispatch to correct type based on discriminator at offset 8."""
    if len(data) < 9:
        return 0

    event_type = data[8]

    if event_type == EVENT_EXEC and len(data) >= ctypes.sizeof(ExecEvent):
        event = ExecEvent.from_buffer_copy(data)
        ts_ms = event.timestamp / 1_000_000
        print(f"{ts_ms:>12.3f} EXEC  pid={event.pid:<6} {event.comm.decode()}")

    elif event_type == EVENT_EXIT and len(data) >= ctypes.sizeof(ExitEvent):
        event = ExitEvent.from_buffer_copy(data)
        ts_ms = event.timestamp / 1_000_000
        print(f"{ts_ms:>12.3f} EXIT  pid={event.pid:<6} code={event.exit_code}")

    return 0


def main() -> None:
    bpf_obj = Path(__file__).parent / "events.bpf.o"

    print(f"Loading {bpf_obj}")
    with tinybpf.load(bpf_obj) as obj:
        # Attach both programs
        link_exec = obj.programs["trace_exec"].attach()
        link_exit = obj.programs["trace_exit"].attach()
        print("Attached to sys_enter_execve and sched_process_exit. Press Ctrl+C to exit.\n")

        # Ring buffer without event_type - we handle dispatch manually
        rb = tinybpf.BpfRingBuffer(obj.maps["events"], handle_event)

        running = True

        def stop(sig, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, stop)

        print(f"{'TIME (ms)':>12} EVENT {'PID':<6} INFO")
        print("-" * 50)
        while running:
            rb.poll(timeout_ms=100)

        print("\nDetaching...")
        link_exec.destroy()
        link_exit.destroy()


if __name__ == "__main__":
    main()
