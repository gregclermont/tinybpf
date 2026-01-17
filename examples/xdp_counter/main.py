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
"""Count packets with XDP and per-CPU maps."""

import ctypes
import signal
import socket
import sys
import time
from pathlib import Path

import tinybpf


class Stats(ctypes.Structure):
    _fields_ = [
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
    ]


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        print(f"Example: {sys.argv[0]} lo")
        sys.exit(1)

    interface = sys.argv[1]

    # Get interface index
    try:
        ifindex = socket.if_nametoindex(interface)
    except OSError:
        print(f"Error: interface '{interface}' not found")
        sys.exit(1)

    bpf_obj = Path(__file__).parent / "counter.bpf.o"

    print(f"Loading {bpf_obj}")
    with tinybpf.load(bpf_obj) as obj:
        # Attach XDP program to interface
        link = obj.programs["xdp_count"].attach_xdp(ifindex)
        print(f"Attached XDP to {interface} (ifindex={ifindex}). Press Ctrl+C to exit.\n")

        # Get typed stats map
        stats_map = obj.maps["stats"].typed(key=ctypes.c_uint32, value=Stats)

        running = True

        def stop(sig, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, stop)

        print(f"{'PACKETS':>12} {'BYTES':>15} {'PPS':>10} {'BPS':>12}")
        print("-" * 55)

        prev_packets = 0
        prev_bytes = 0
        prev_time = time.time()

        while running:
            time.sleep(1)

            # Read per-CPU values and sum them
            per_cpu_values = stats_map.lookup_percpu(0)
            if per_cpu_values is None:
                continue

            total_packets = sum(v.packets for v in per_cpu_values)
            total_bytes = sum(v.bytes for v in per_cpu_values)

            # Calculate rates
            now = time.time()
            elapsed = now - prev_time
            pps = (total_packets - prev_packets) / elapsed
            bps = (total_bytes - prev_bytes) / elapsed

            print(f"{total_packets:>12} {total_bytes:>15} {pps:>10.1f} {bps:>12.1f}")

            prev_packets = total_packets
            prev_bytes = total_bytes
            prev_time = now

        print("\nDetaching...")
        link.destroy()


if __name__ == "__main__":
    main()
