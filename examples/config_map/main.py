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
"""Demonstrate config maps for userspace-to-BPF configuration."""

import ctypes
import os
import signal
import time
from pathlib import Path

import tinybpf


class Config(ctypes.Structure):
    _fields_ = [
        ("target_pid", ctypes.c_uint32),
        ("enabled", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 3),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]


def handle_event(event: Event) -> int:
    print(f"  pid={event.pid:<6} {event.comm.decode()}")
    return 0


def main() -> None:
    bpf_obj = Path(__file__).parent / "filter.bpf.o"

    print(f"Loading {bpf_obj}")
    with tinybpf.load(bpf_obj) as obj:
        # Get typed access to config map
        config_map = obj.maps["config"].typed(
            key=ctypes.c_uint32, value=Config
        )

        # Attach to tracepoint
        link = obj.programs["trace_execve"].attach()
        print("Attached to sys_enter_execve.\n")

        # Ring buffer
        rb = tinybpf.BpfRingBuffer(
            obj.maps["events"], handle_event, event_type=Event
        )

        running = True

        def stop(sig, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, stop)

        # Demo: change config over time
        shell_pid = os.getppid()

        print("Phase 1: No filter (all PIDs)")
        print("-" * 40)
        config_map[0] = Config(target_pid=0, enabled=0)

        start = time.time()
        while running and time.time() - start < 5:
            rb.poll(timeout_ms=100)

        if not running:
            return

        print(f"\nPhase 2: Filter to shell PID {shell_pid}")
        print("-" * 40)
        config_map[0] = Config(target_pid=shell_pid, enabled=1)

        start = time.time()
        while running and time.time() - start < 5:
            rb.poll(timeout_ms=100)

        if not running:
            return

        print("\nPhase 3: Filter disabled again")
        print("-" * 40)
        config_map[0] = Config(target_pid=0, enabled=0)

        while running:
            rb.poll(timeout_ms=100)

        print("\nDetaching...")
        link.destroy()


if __name__ == "__main__":
    main()
