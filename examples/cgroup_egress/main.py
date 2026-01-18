#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "tinybpf",
# ]
#
# [[tool.uv.index]]
# url = "https://gregclermont.github.io/tinybpf"
# ///
"""Cgroup egress packet counter example.

Attaches a BPF program to the current process's cgroup that counts
all outgoing network packets. Run with sudo.
"""

import time
from pathlib import Path

import tinybpf


def get_current_cgroup() -> str:
    """Get the cgroup path for the current process."""
    with open("/proc/self/cgroup") as f:
        for line in f:
            parts = line.strip().split(":")
            if parts[0] == "0":  # cgroup v2
                return f"/sys/fs/cgroup{parts[2]}"
    raise RuntimeError("cgroup v2 not found")


def main():
    bpf_path = Path(__file__).parent / "egress_filter.bpf.o"
    cgroup_path = get_current_cgroup()

    print(f"Loading BPF program from {bpf_path}")
    print(f"Attaching to cgroup: {cgroup_path}")

    with tinybpf.load(bpf_path) as obj:
        prog = obj.program("count_egress")
        packet_count = obj.maps["packet_count"]

        with prog.attach_cgroup(cgroup_path):
            print("Counting egress packets. Press Ctrl+C to stop.\n")

            try:
                while True:
                    count = packet_count[0]
                    print(f"\rPackets: {count}", end="", flush=True)
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print(f"\n\nTotal packets: {packet_count[0]}")


if __name__ == "__main__":
    main()
