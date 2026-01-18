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
"""Trace process execution using tracepoint on sys_enter_execve."""

import ctypes
from pathlib import Path

import tinybpf


class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]


def handle_event(event: Event) -> int:
    print(f"pid={event.pid:<6} uid={event.uid:<5} comm={event.comm.decode()}")
    return 0


def main() -> None:
    bpf_obj = Path(__file__).parent / "trace_exec.bpf.o"

    print(f"Loading {bpf_obj}")
    with tinybpf.load(bpf_obj) as obj:
        # Attach to execve tracepoint
        link = obj.programs["trace_execve"].attach()
        print("Attached to sys_enter_execve. Press Ctrl+C to exit.\n")

        # Set up ring buffer with typed events
        rb = tinybpf.BpfRingBuffer(
            obj.maps["events"], handle_event, event_type=Event
        )

        # Poll for events
        print(f"{'PID':<6} {'UID':<5} COMM")
        print("-" * 30)
        try:
            while True:
                rb.poll(timeout_ms=100)
        except KeyboardInterrupt:
            print("\nDetaching...")
            link.destroy()


if __name__ == "__main__":
    main()
