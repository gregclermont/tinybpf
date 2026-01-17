#!/usr/bin/env python3
"""
XDP Packet Filter - Demonstrate packet filtering with eBPF/XDP

This example demonstrates:
- Loading and attaching XDP programs
- Configuring filter rules via BPF maps
- IP blocklist management
- Rate limiting by source IP
- Real-time packet statistics
- Drop event logging via ring buffer

Requirements:
- Linux kernel 5.8+ (for ring buffers, 4.8+ for basic XDP)
- Root/CAP_NET_ADMIN privileges
- Network interface to attach to

Usage:
    # Stats-only mode (no filtering)
    sudo python3 xdp_filter.py --interface eth0 --mode stats

    # Full filtering mode
    sudo python3 xdp_filter.py --interface eth0

    # Block specific IPs
    sudo python3 xdp_filter.py --interface eth0 --block 1.2.3.4 --block 5.6.7.8

    # Rate limiting
    sudo python3 xdp_filter.py --interface eth0 --rate-limit 1000
"""

import argparse
import ctypes
import signal
import socket
import struct
import sys
import time
from pathlib import Path

import tinybpf
from tinybpf._libbpf import bindings

# Protocol numbers
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

PROTO_NAMES = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


class PktStats(ctypes.Structure):
    """Packet statistics per protocol."""

    _fields_ = [
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
        ("dropped", ctypes.c_uint64),
    ]


class XdpConfig(ctypes.Structure):
    """XDP filter configuration."""

    _fields_ = [
        ("enable_blocklist", ctypes.c_uint8),
        ("enable_rate_limit", ctypes.c_uint8),
        ("log_drops", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8),
        ("rate_limit_pps", ctypes.c_uint32),
        ("rate_window_ns", ctypes.c_uint32),
    ]


class DropEvent(ctypes.Structure):
    """Dropped packet event from BPF."""

    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("reason", ctypes.c_uint8),
        ("pkt_len", ctypes.c_uint16),
    ]


DROP_REASONS = {
    1: "BLOCKLIST",
    2: "RATE_LIMIT",
}

COUNTER_TOTAL_PKTS = 0
COUNTER_TOTAL_BYTES = 1
COUNTER_DROPPED = 2
COUNTER_PASSED = 3


def ip4_to_str(addr: int) -> str:
    """Convert IPv4 address (network byte order) to string."""
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(addr)))


def ip4_from_str(addr_str: str) -> int:
    """Convert IPv4 address string to network byte order integer."""
    packed = socket.inet_aton(addr_str)
    return struct.unpack("!I", packed)[0]


def format_bytes(n: int) -> str:
    """Format byte count in human-readable form."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def format_pps(pps: float) -> str:
    """Format packets per second."""
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f}M"
    elif pps >= 1_000:
        return f"{pps / 1_000:.2f}K"
    else:
        return f"{pps:.1f}"


def get_interface_index(ifname: str) -> int:
    """Get interface index by name."""
    import fcntl
    SIOCGIFINDEX = 0x8933
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sI", ifname.encode(), 0)
        res = fcntl.ioctl(sock.fileno(), SIOCGIFINDEX, ifreq)
        return struct.unpack("16sI", res)[1]
    finally:
        sock.close()


class XdpFilter:
    """XDP-based packet filter."""

    def __init__(
        self,
        bpf_path: str,
        interface: str,
        mode: str = "filter",
        blocked_ips: list[str] | None = None,
        rate_limit_pps: int = 0,
        log_drops: bool = True,
        verbose: bool = False,
    ):
        self.interface = interface
        self.verbose = verbose
        self.running = True
        self.drop_count = 0

        # Load BPF program
        print(f"Loading BPF program from {bpf_path}...")
        self.obj = tinybpf.load(bpf_path)

        # Register types
        self.obj.register_type("pkt_stats", PktStats)
        self.obj.register_type("drop_event", DropEvent)

        # Get maps
        self.proto_stats_map = self.obj.maps["proto_stats"]
        self.blocked_ips_map = self.obj.maps["blocked_ips"]
        self.config_map = self.obj.maps["config"]
        self.counters_map = self.obj.maps["counters"]
        self.drop_events_map = self.obj.maps["drop_events"]

        # Select program based on mode
        program_name = {
            "filter": "xdp_filter",
            "stats": "xdp_stats_only",
            "pass": "xdp_pass",
            "drop": "xdp_drop",
        }.get(mode, "xdp_filter")

        self.prog = self.obj.program(program_name)
        print(f"  Using program: {program_name}")

        # Configure filter
        config = XdpConfig()
        config.enable_blocklist = 1 if blocked_ips else 0
        config.enable_rate_limit = 1 if rate_limit_pps > 0 else 0
        config.log_drops = 1 if log_drops else 0
        config.rate_limit_pps = rate_limit_pps
        config.rate_window_ns = 1_000_000_000  # 1 second window

        key = ctypes.c_uint32(0)
        self.config_map[bytes(key)] = bytes(config)

        # Add blocked IPs
        if blocked_ips:
            print(f"  Blocking {len(blocked_ips)} IPs:")
            for ip in blocked_ips:
                self.block_ip(ip)
                print(f"    - {ip}")

        if rate_limit_pps > 0:
            print(f"  Rate limit: {rate_limit_pps} pps per source IP")

        # Create ring buffer for drop events
        self.ring_buffer = tinybpf.BpfRingBuffer(
            self.drop_events_map, callback=self._handle_drop_event
        )

        # Get interface index and attach
        self.ifindex = get_interface_index(interface)
        print(f"  Attaching to {interface} (ifindex={self.ifindex})...")
        self.link = self.prog.attach_xdp(self.ifindex)

        print(f"\nXDP filter active on {interface}. Press Ctrl+C to stop.\n")

    def block_ip(self, ip_str: str):
        """Add IP to blocklist."""
        ip_int = ip4_from_str(ip_str)
        key = struct.pack("!I", ip_int)
        value = struct.pack("B", 1)
        self.blocked_ips_map[key] = value

    def unblock_ip(self, ip_str: str):
        """Remove IP from blocklist."""
        ip_int = ip4_from_str(ip_str)
        key = struct.pack("!I", ip_int)
        try:
            del self.blocked_ips_map[key]
        except KeyError:
            pass

    def _handle_drop_event(self, data: bytes) -> int:
        """Handle drop event from ring buffer."""
        if not self.running:
            return -1

        try:
            event = DropEvent.from_buffer_copy(data)
            reason = DROP_REASONS.get(event.reason, f"UNKNOWN({event.reason})")
            proto = PROTO_NAMES.get(event.protocol, f"proto{event.protocol}")

            saddr = ip4_to_str(event.saddr)
            daddr = ip4_to_str(event.daddr)

            if event.sport or event.dport:
                print(
                    f"DROP [{reason:>10}] {proto:>6} {saddr}:{event.sport} -> "
                    f"{daddr}:{event.dport} ({event.pkt_len} bytes)"
                )
            else:
                print(
                    f"DROP [{reason:>10}] {proto:>6} {saddr} -> "
                    f"{daddr} ({event.pkt_len} bytes)"
                )

            self.drop_count += 1

        except Exception as e:
            if self.verbose:
                print(f"Error processing drop event: {e}", file=sys.stderr)

        return 0

    def get_counters(self) -> dict[str, int]:
        """Get global counters (summed across CPUs)."""
        counters = {}
        names = ["total_pkts", "total_bytes", "dropped", "passed"]

        for idx, name in enumerate(names):
            try:
                key = struct.pack("I", idx)
                values = self.counters_map[key]
                # Sum per-CPU values (each is uint64 = 8 bytes)
                total = 0
                for i in range(0, len(values), 8):
                    total += int.from_bytes(values[i : i + 8], "little")
                counters[name] = total
            except Exception:
                counters[name] = 0

        return counters

    def get_proto_stats(self) -> dict[str, PktStats]:
        """Get per-protocol statistics."""
        stats = {}

        for proto, name in PROTO_NAMES.items():
            try:
                key = struct.pack("I", proto)
                values = self.proto_stats_map[key]

                # Sum per-CPU values
                total = PktStats()
                cpu_size = ctypes.sizeof(PktStats)
                num_cpus = len(values) // cpu_size

                for i in range(num_cpus):
                    offset = i * cpu_size
                    cpu_stats = PktStats.from_buffer_copy(
                        values[offset : offset + cpu_size]
                    )
                    total.packets += cpu_stats.packets
                    total.bytes += cpu_stats.bytes
                    total.dropped += cpu_stats.dropped

                if total.packets > 0:
                    stats[name] = total
            except Exception:
                pass

        return stats

    def print_stats(self):
        """Print current statistics."""
        counters = self.get_counters()
        proto_stats = self.get_proto_stats()

        print("\n" + "=" * 60)
        print(f"XDP Filter Statistics - {self.interface}")
        print("=" * 60)

        print(f"\nGlobal Counters:")
        print(f"  Total packets:  {counters.get('total_pkts', 0):>15,}")
        print(f"  Total bytes:    {format_bytes(counters.get('total_bytes', 0)):>15}")
        print(f"  Passed:         {counters.get('passed', 0):>15,}")
        print(f"  Dropped:        {counters.get('dropped', 0):>15,}")

        if proto_stats:
            print(f"\nPer-Protocol Statistics:")
            print(f"  {'Protocol':<10} {'Packets':>12} {'Bytes':>12} {'Dropped':>12}")
            print(f"  {'-' * 10} {'-' * 12} {'-' * 12} {'-' * 12}")
            for name, stats in sorted(
                proto_stats.items(), key=lambda x: -x[1].packets
            ):
                print(
                    f"  {name:<10} {stats.packets:>12,} "
                    f"{format_bytes(stats.bytes):>12} {stats.dropped:>12,}"
                )

    def run(self, stats_interval: int = 5):
        """Main loop with periodic stats display."""
        last_stats_time = time.time()
        last_counters = self.get_counters()

        try:
            while self.running:
                # Poll for drop events
                self.ring_buffer.poll(timeout_ms=100)

                # Periodic stats
                now = time.time()
                if now - last_stats_time >= stats_interval:
                    current = self.get_counters()

                    # Calculate rates
                    elapsed = now - last_stats_time
                    pkt_rate = (
                        current.get("total_pkts", 0)
                        - last_counters.get("total_pkts", 0)
                    ) / elapsed
                    byte_rate = (
                        current.get("total_bytes", 0)
                        - last_counters.get("total_bytes", 0)
                    ) / elapsed
                    drop_rate = (
                        current.get("dropped", 0) - last_counters.get("dropped", 0)
                    ) / elapsed

                    print(
                        f"[{time.strftime('%H:%M:%S')}] "
                        f"Pkts: {format_pps(pkt_rate)} pps | "
                        f"Throughput: {format_bytes(byte_rate)}/s | "
                        f"Drops: {format_pps(drop_rate)} pps | "
                        f"Total drops: {current.get('dropped', 0):,}"
                    )

                    last_stats_time = now
                    last_counters = current

        except KeyboardInterrupt:
            pass

    def stop(self):
        """Stop filter and print final stats."""
        self.running = False
        self.print_stats()
        print(f"\nDrop events captured: {self.drop_count}")

    def close(self):
        """Clean up resources."""
        print(f"\nDetaching XDP from {self.interface}...")
        self.link.destroy()
        self.obj.close()


def main():
    parser = argparse.ArgumentParser(
        description="XDP packet filter with tinybpf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Stats-only mode (no filtering)
  sudo python3 xdp_filter.py --interface eth0 --mode stats

  # Block specific IPs
  sudo python3 xdp_filter.py --interface eth0 --block 1.2.3.4

  # Rate limiting (1000 pps per source IP)
  sudo python3 xdp_filter.py --interface eth0 --rate-limit 1000
""",
    )
    parser.add_argument(
        "--bpf",
        default=str(Path(__file__).parent / "bpf" / "xdp_filter.bpf.o"),
        help="Path to compiled BPF object file",
    )
    parser.add_argument(
        "--interface", "-i", required=True, help="Network interface to attach to"
    )
    parser.add_argument(
        "--mode",
        choices=["filter", "stats", "pass", "drop"],
        default="filter",
        help="XDP program mode (default: filter)",
    )
    parser.add_argument(
        "--block",
        "-b",
        action="append",
        default=[],
        help="IP address to block (can be specified multiple times)",
    )
    parser.add_argument(
        "--rate-limit",
        "-r",
        type=int,
        default=0,
        help="Rate limit in packets per second per source IP (0 = disabled)",
    )
    parser.add_argument(
        "--no-log-drops",
        action="store_true",
        help="Don't log dropped packets",
    )
    parser.add_argument(
        "--stats-interval",
        type=int,
        default=5,
        help="Statistics display interval in seconds (default: 5)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )
    parser.add_argument(
        "--libbpf", type=str, help="Path to libbpf.so"
    )

    args = parser.parse_args()

    # Initialize tinybpf
    if args.libbpf:
        bindings.init(libbpf_path=args.libbpf)

    xdp = XdpFilter(
        bpf_path=args.bpf,
        interface=args.interface,
        mode=args.mode,
        blocked_ips=args.block if args.block else None,
        rate_limit_pps=args.rate_limit,
        log_drops=not args.no_log_drops,
        verbose=args.verbose,
    )

    signal.signal(signal.SIGINT, lambda s, f: xdp.stop())
    signal.signal(signal.SIGTERM, lambda s, f: xdp.stop())

    try:
        xdp.run(stats_interval=args.stats_interval)
    finally:
        xdp.close()


if __name__ == "__main__":
    main()
