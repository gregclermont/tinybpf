#!/usr/bin/env python3
"""
Network Connection Tracker - Monitor TCP connections with eBPF

This example demonstrates:
- Loading BPF programs with tinybpf
- Attaching kprobes and kretprobes
- Using ring buffers for event streaming
- IP address formatting and connection tracking
- Per-port statistics with BPF hash maps

Requirements:
- Linux kernel 5.8+ (for ring buffers)
- Root/CAP_BPF privileges
"""

import argparse
import ctypes
import signal
import socket
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path

import tinybpf
from tinybpf._libbpf import bindings

# Event types
CONN_CONNECT = 1
CONN_ACCEPT = 2
CONN_CLOSE = 3

TASK_COMM_LEN = 16


class ConnEventV4(ctypes.Structure):
    """IPv4 connection event from BPF."""

    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("protocol", ctypes.c_uint8),
        ("family", ctypes.c_uint16),
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("bytes_sent", ctypes.c_uint64),
        ("bytes_recv", ctypes.c_uint64),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class ConnEventV6(ctypes.Structure):
    """IPv6 connection event from BPF."""

    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("protocol", ctypes.c_uint8),
        ("family", ctypes.c_uint16),
        ("saddr", ctypes.c_uint8 * 16),
        ("daddr", ctypes.c_uint8 * 16),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("bytes_sent", ctypes.c_uint64),
        ("bytes_recv", ctypes.c_uint64),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class FilterConfig(ctypes.Structure):
    """Filter configuration for BPF."""

    _fields_ = [
        ("target_pid", ctypes.c_uint32),
        ("target_port", ctypes.c_uint16),
        ("track_ipv4", ctypes.c_uint8),
        ("track_ipv6", ctypes.c_uint8),
    ]


class PortStats(ctypes.Structure):
    """Per-port statistics."""

    _fields_ = [
        ("connections", ctypes.c_uint64),
        ("bytes_sent", ctypes.c_uint64),
        ("bytes_recv", ctypes.c_uint64),
    ]


def ip4_to_str(addr: int) -> str:
    """Convert IPv4 address (network byte order) to string."""
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(addr)))


def ip6_to_str(addr: bytes) -> str:
    """Convert IPv6 address bytes to string."""
    return socket.inet_ntop(socket.AF_INET6, bytes(addr))


def format_timestamp(ns: int) -> str:
    """Format nanosecond timestamp."""
    secs = ns // 1_000_000_000
    msecs = (ns % 1_000_000_000) // 1_000_000
    return f"{secs:>10}.{msecs:03}"


def decode_comm(comm: bytes) -> str:
    """Decode comm field."""
    try:
        return comm.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return comm.hex()


EVENT_NAMES = {
    CONN_CONNECT: "CONNECT",
    CONN_ACCEPT: "ACCEPT",
    CONN_CLOSE: "CLOSE",
}


class NetworkTracker:
    """Track network connections using eBPF."""

    def __init__(
        self,
        bpf_path: str,
        target_pid: int = 0,
        target_port: int = 0,
        show_closes: bool = True,
        verbose: bool = False,
    ):
        self.show_closes = show_closes
        self.verbose = verbose
        self.running = True
        self.event_count = 0

        # Connection tracking
        self.active_connections: dict[tuple, dict] = {}
        self.stats_by_pid: dict[int, dict] = defaultdict(
            lambda: {"connects": 0, "accepts": 0, "closes": 0}
        )
        self.stats_by_port: dict[int, int] = defaultdict(int)

        # Load BPF program
        print(f"Loading BPF program from {bpf_path}...")
        self.obj = tinybpf.load(bpf_path)

        # Register event types
        self.obj.register_type("conn_event_v4", ConnEventV4)
        self.obj.register_type("conn_event_v6", ConnEventV6)

        # Get maps
        self.events_map = self.obj.maps["events"]
        self.config_map = self.obj.maps["config"]
        self.port_stats_map = self.obj.maps["port_stats_map"]

        # Configure filter
        config = FilterConfig()
        config.target_pid = target_pid
        config.target_port = target_port
        config.track_ipv4 = 1
        config.track_ipv6 = 1

        key = ctypes.c_uint32(0)
        self.config_map[bytes(key)] = bytes(config)

        if target_pid:
            print(f"  Filtering by PID: {target_pid}")
        if target_port:
            print(f"  Filtering by port: {target_port}")

        # Create ring buffer
        self.ring_buffer = tinybpf.BpfRingBuffer(
            self.events_map, callback=self._handle_event
        )

        # Attach programs
        self._links = []
        for name, prog in self.obj.programs.items():
            print(f"  Attaching {name} ({prog.section})...")
            try:
                link = prog.attach()
                self._links.append(link)
            except tinybpf.BpfError as e:
                print(f"    Warning: Could not attach {name}: {e}")

        print("\nNetwork tracker started. Press Ctrl+C to stop.\n")
        self._print_header()

    def _print_header(self):
        """Print column header."""
        print(
            f"{'TIME':<14} {'EVENT':<8} {'PID':>7} {'COMM':<16} "
            f"{'LOCAL':<21} {'REMOTE':<21}"
        )
        print("-" * 100)

    def _handle_event(self, data: bytes) -> int:
        """Handle incoming event from ring buffer."""
        if not self.running:
            return -1

        try:
            # Parse as IPv4 event (most common)
            if len(data) >= ctypes.sizeof(ConnEventV4):
                event = ConnEventV4.from_buffer_copy(data)

                # Check if it's actually IPv4 (family=2)
                if event.family == 2:
                    self._handle_v4_event(event)
                    return 0

            # Try IPv6
            if len(data) >= ctypes.sizeof(ConnEventV6):
                event = ConnEventV6.from_buffer_copy(data)
                if event.family == 10:  # AF_INET6
                    self._handle_v6_event(event)
                    return 0

        except Exception as e:
            if self.verbose:
                print(f"Error processing event: {e}", file=sys.stderr)

        return 0

    def _handle_v4_event(self, e: ConnEventV4):
        """Handle IPv4 connection event."""
        event_name = EVENT_NAMES.get(e.event_type, "UNKNOWN")

        if e.event_type == CONN_CLOSE and not self.show_closes:
            return

        comm = decode_comm(e.comm)
        local_ip = ip4_to_str(e.saddr)
        remote_ip = ip4_to_str(e.daddr)
        local = f"{local_ip}:{e.sport}"
        remote = f"{remote_ip}:{e.dport}"

        print(
            f"{format_timestamp(e.timestamp)} {event_name:<8} {e.tgid:>7} "
            f"{comm:<16} {local:<21} {remote:<21}"
        )

        # Update stats
        self.event_count += 1
        self.stats_by_pid[e.tgid][event_name.lower() + "s"] += 1
        self.stats_by_port[e.dport] += 1

        # Track active connections
        conn_key = (e.saddr, e.sport, e.daddr, e.dport)
        if e.event_type == CONN_CONNECT:
            self.active_connections[conn_key] = {
                "pid": e.tgid,
                "comm": comm,
                "start": e.timestamp,
            }
        elif e.event_type == CONN_CLOSE:
            self.active_connections.pop(conn_key, None)

    def _handle_v6_event(self, e: ConnEventV6):
        """Handle IPv6 connection event."""
        event_name = EVENT_NAMES.get(e.event_type, "UNKNOWN")

        if e.event_type == CONN_CLOSE and not self.show_closes:
            return

        comm = decode_comm(e.comm)
        local_ip = ip6_to_str(e.saddr)
        remote_ip = ip6_to_str(e.daddr)
        local = f"[{local_ip}]:{e.sport}"
        remote = f"[{remote_ip}]:{e.dport}"

        # Truncate for display
        if len(local) > 21:
            local = local[:18] + "..."
        if len(remote) > 21:
            remote = remote[:18] + "..."

        print(
            f"{format_timestamp(e.timestamp)} {event_name:<8} {e.tgid:>7} "
            f"{comm:<16} {local:<21} {remote:<21}"
        )

        self.event_count += 1
        self.stats_by_pid[e.tgid][event_name.lower() + "s"] += 1

    def get_port_stats(self) -> dict[int, int]:
        """Get per-port connection counts from BPF map."""
        stats = {}
        try:
            for key, value in self.port_stats_map.items():
                port = struct.unpack("H", key)[0]
                ps = PortStats.from_buffer_copy(value)
                stats[port] = ps.connections
        except Exception as e:
            if self.verbose:
                print(f"Error reading port stats: {e}")
        return stats

    def run(self, timeout_ms: int = 100):
        """Main event loop."""
        try:
            while self.running:
                self.ring_buffer.poll(timeout_ms=timeout_ms)
        except KeyboardInterrupt:
            pass

    def stop(self):
        """Stop tracking and print summary."""
        self.running = False

        print("\n" + "=" * 100)
        print("Network Tracker Summary")
        print("=" * 100)

        print(f"\nTotal events captured: {self.event_count}")
        print(f"Active connections: {len(self.active_connections)}")

        # Top processes by connection count
        if self.stats_by_pid:
            print("\nTop processes by activity:")
            sorted_pids = sorted(
                self.stats_by_pid.items(),
                key=lambda x: sum(x[1].values()),
                reverse=True,
            )[:10]
            for pid, stats in sorted_pids:
                total = sum(stats.values())
                print(
                    f"  PID {pid:>7}: {total:>5} events "
                    f"(connects={stats.get('connects', 0)}, "
                    f"accepts={stats.get('accepts', 0)}, "
                    f"closes={stats.get('closes', 0)})"
                )

        # Top destination ports
        if self.stats_by_port:
            print("\nTop destination ports:")
            sorted_ports = sorted(
                self.stats_by_port.items(), key=lambda x: x[1], reverse=True
            )[:10]
            for port, count in sorted_ports:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = ""
                print(f"  Port {port:>5} ({service:>10}): {count} connections")

        # BPF-side port stats
        bpf_stats = self.get_port_stats()
        if bpf_stats:
            print("\nBPF port statistics (kernel-side):")
            for port, count in sorted(bpf_stats.items(), key=lambda x: -x[1])[:10]:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = ""
                print(f"  Port {port:>5} ({service:>10}): {count} connections")

    def close(self):
        """Clean up resources."""
        for link in self._links:
            link.destroy()
        self.obj.close()


def main():
    parser = argparse.ArgumentParser(
        description="Track TCP connections with eBPF"
    )
    parser.add_argument(
        "--bpf",
        default=str(Path(__file__).parent / "bpf" / "network_tracker.bpf.o"),
        help="Path to compiled BPF object file",
    )
    parser.add_argument(
        "--pid", "-p", type=int, default=0, help="Filter by PID (0 = all)"
    )
    parser.add_argument(
        "--port", type=int, default=0, help="Filter by port (0 = all)"
    )
    parser.add_argument(
        "--no-closes", action="store_true", help="Don't show close events"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )
    parser.add_argument(
        "--libbpf", type=str, help="Path to libbpf.so"
    )
    parser.add_argument(
        "--duration", "-d", type=int, default=0,
        help="Duration to run in seconds (0 = until Ctrl+C)"
    )

    args = parser.parse_args()

    # Initialize tinybpf
    if args.libbpf:
        bindings.init(libbpf_path=args.libbpf)

    tracker = NetworkTracker(
        bpf_path=args.bpf,
        target_pid=args.pid,
        target_port=args.port,
        show_closes=not args.no_closes,
        verbose=args.verbose,
    )

    signal.signal(signal.SIGINT, lambda s, f: tracker.stop())
    signal.signal(signal.SIGTERM, lambda s, f: tracker.stop())

    try:
        if args.duration > 0:
            end_time = time.time() + args.duration
            while tracker.running and time.time() < end_time:
                tracker.ring_buffer.poll(timeout_ms=100)
            tracker.stop()
        else:
            tracker.run()
    finally:
        tracker.close()


if __name__ == "__main__":
    main()
