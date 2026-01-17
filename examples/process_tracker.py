#!/usr/bin/env python3
"""
Process Tracker - Monitor process execution, forks, and exits with eBPF

This example demonstrates:
- Loading BPF programs with tinybpf
- Using ring buffers for event streaming
- Type inference from BTF metadata
- Statistics tracking with per-CPU arrays
- Process lifecycle monitoring

Requirements:
- Linux kernel 5.8+ (for ring buffers)
- Root/CAP_BPF privileges
"""

import argparse
import ctypes
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

import tinybpf
from tinybpf._libbpf import bindings

# Event types
EVENT_EXEC = 1
EVENT_FORK = 2
EVENT_EXIT = 3

TASK_COMM_LEN = 16
MAX_FILENAME_LEN = 256
MAX_ARGS_LEN = 256


class ExecEvent(ctypes.Structure):
    """Process execution event from BPF."""

    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * MAX_FILENAME_LEN),
        ("args", ctypes.c_char * MAX_ARGS_LEN),
        ("args_count", ctypes.c_int32),
        ("args_size", ctypes.c_int32),
    ]


class ForkEvent(ctypes.Structure):
    """Process fork event from BPF."""

    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("parent_pid", ctypes.c_uint32),
        ("parent_tgid", ctypes.c_uint32),
        ("child_pid", ctypes.c_uint32),
        ("child_tgid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("parent_comm", ctypes.c_char * TASK_COMM_LEN),
        ("child_comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class ExitEvent(ctypes.Structure):
    """Process exit event from BPF."""

    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("exit_code", ctypes.c_int32),
        ("duration_ns", ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


def format_timestamp(ns: int) -> str:
    """Format nanosecond timestamp as human-readable time."""
    # Note: This is monotonic time from boot, not wall clock
    secs = ns // 1_000_000_000
    msecs = (ns % 1_000_000_000) // 1_000_000
    return f"{secs:>10}.{msecs:03}"


def format_duration(ns: int) -> str:
    """Format duration in human-readable form."""
    if ns == 0:
        return "N/A"
    if ns < 1_000:
        return f"{ns}ns"
    elif ns < 1_000_000:
        return f"{ns / 1_000:.1f}μs"
    elif ns < 1_000_000_000:
        return f"{ns / 1_000_000:.1f}ms"
    else:
        return f"{ns / 1_000_000_000:.2f}s"


def decode_comm(comm: bytes) -> str:
    """Decode comm field, handling null termination."""
    try:
        return comm.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return comm.hex()


def decode_str(s: bytes) -> str:
    """Decode a byte string, handling embedded nulls."""
    try:
        # Find first null or decode entire string
        null_idx = s.find(b"\x00")
        if null_idx >= 0:
            s = s[:null_idx]
        return s.decode("utf-8", errors="replace")
    except Exception:
        return s.hex()


class ProcessTracker:
    """Track process lifecycle events using eBPF."""

    def __init__(
        self,
        bpf_path: str,
        show_forks: bool = True,
        show_exits: bool = True,
        filter_comm: str | None = None,
        verbose: bool = False,
    ):
        self.show_forks = show_forks
        self.show_exits = show_exits
        self.filter_comm = filter_comm
        self.verbose = verbose
        self.running = True
        self.event_count = 0

        # Load BPF program
        print(f"Loading BPF program from {bpf_path}...")
        self.obj = tinybpf.load(bpf_path)

        # Register event types for BTF validation
        self.obj.register_type("exec_event", ExecEvent)
        self.obj.register_type("fork_event", ForkEvent)
        self.obj.register_type("exit_event", ExitEvent)

        # Get maps
        self.events_map = self.obj.maps["events"]
        self.stats_map = self.obj.maps["stats"]

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

        print("Process tracker started. Press Ctrl+C to stop.\n")
        self._print_header()

    def _print_header(self):
        """Print column header."""
        print(f"{'TIME':<14} {'EVENT':<5} {'PID':>7} {'PPID':>7} {'UID':>5} "
              f"{'COMM':<16} {'DETAILS'}")
        print("-" * 100)

    def _handle_event(self, data: bytes) -> int:
        """Handle incoming event from ring buffer."""
        if not self.running:
            return -1  # Stop polling

        # Peek at event type (offset depends on struct layout)
        # event_type is after timestamp(8) + pid(4) + tgid(4) + ppid(4) + uid(4) + gid(4)
        # = offset 28 for exec_event
        # For safety, we'll check size and decode appropriately

        try:
            if len(data) >= ctypes.sizeof(ExecEvent):
                # Try as exec event first
                event = ExecEvent.from_buffer_copy(data)
                if event.event_type == EVENT_EXEC:
                    self._handle_exec(event)
                    return 0

            if len(data) >= ctypes.sizeof(ExitEvent):
                event = ExitEvent.from_buffer_copy(data)
                if event.event_type == EVENT_EXIT:
                    self._handle_exit(event)
                    return 0

            if len(data) >= ctypes.sizeof(ForkEvent):
                event = ForkEvent.from_buffer_copy(data)
                if event.event_type == EVENT_FORK:
                    self._handle_fork(event)
                    return 0

        except Exception as e:
            if self.verbose:
                print(f"Error processing event: {e}", file=sys.stderr)

        return 0

    def _should_filter(self, comm: str) -> bool:
        """Check if event should be filtered out."""
        if self.filter_comm:
            return self.filter_comm.lower() not in comm.lower()
        return False

    def _handle_exec(self, e: ExecEvent):
        """Handle exec event."""
        comm = decode_comm(e.comm)
        if self._should_filter(comm):
            return

        filename = decode_str(e.filename)
        args = decode_str(e.args)

        # Truncate long args for display
        max_args_display = 60
        if len(args) > max_args_display:
            args = args[:max_args_display] + "..."

        print(
            f"{format_timestamp(e.timestamp)} {'EXEC':<5} {e.pid:>7} {e.ppid:>7} "
            f"{e.uid:>5} {comm:<16} {filename}"
        )
        if args and self.verbose:
            print(f"{'':14} {'':5} {'':7} {'':7} {'':5} {'':16} Args: {args}")

        self.event_count += 1

    def _handle_fork(self, e: ForkEvent):
        """Handle fork event."""
        if not self.show_forks:
            return

        parent_comm = decode_comm(e.parent_comm)
        child_comm = decode_comm(e.child_comm)

        if self._should_filter(parent_comm) and self._should_filter(child_comm):
            return

        print(
            f"{format_timestamp(e.timestamp)} {'FORK':<5} {e.child_pid:>7} "
            f"{e.parent_pid:>7} {'':>5} {child_comm:<16} "
            f"parent={parent_comm}[{e.parent_pid}]"
        )

        self.event_count += 1

    def _handle_exit(self, e: ExitEvent):
        """Handle exit event."""
        if not self.show_exits:
            return

        comm = decode_comm(e.comm)
        if self._should_filter(comm):
            return

        duration_str = format_duration(e.duration_ns)
        exit_info = f"code={e.exit_code}"
        if e.duration_ns > 0:
            exit_info += f" duration={duration_str}"

        print(
            f"{format_timestamp(e.timestamp)} {'EXIT':<5} {e.pid:>7} "
            f"{e.ppid:>7} {'':>5} {comm:<16} {exit_info}"
        )

        self.event_count += 1

    def _get_stats(self) -> dict[str, int]:
        """Get statistics from the per-CPU array."""
        stats = {}
        stat_names = ["exec_count", "fork_count", "exit_count", "error_count"]

        for idx, name in enumerate(stat_names):
            try:
                # Per-CPU values need to be summed
                key = ctypes.c_uint32(idx)
                key_bytes = bytes(key)
                values = self.stats_map[key_bytes]
                # Values is bytes of per-CPU array, sum them
                # Each value is uint64 (8 bytes)
                total = 0
                for i in range(0, len(values), 8):
                    total += int.from_bytes(values[i : i + 8], "little")
                stats[name] = total
            except Exception:
                stats[name] = 0

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
        print("Process Tracker Summary")
        print("=" * 100)

        stats = self._get_stats()
        print(f"Events captured: {self.event_count}")
        print(f"BPF statistics:")
        for name, value in stats.items():
            print(f"  {name}: {value}")

    def close(self):
        """Clean up resources."""
        for link in self._links:
            link.destroy()
        self.obj.close()


def main():
    parser = argparse.ArgumentParser(
        description="Track process execution, forks, and exits with eBPF"
    )
    parser.add_argument(
        "--bpf",
        default=str(Path(__file__).parent / "bpf" / "process_tracker.bpf.o"),
        help="Path to compiled BPF object file",
    )
    parser.add_argument(
        "--no-forks", action="store_true", help="Don't show fork events"
    )
    parser.add_argument(
        "--no-exits", action="store_true", help="Don't show exit events"
    )
    parser.add_argument(
        "--filter", "-f", type=str, help="Filter by command name (substring match)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show verbose output"
    )
    parser.add_argument(
        "--libbpf",
        type=str,
        help="Path to libbpf.so (default: use bundled)",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=0,
        help="Duration to run in seconds (0 = until Ctrl+C)",
    )

    args = parser.parse_args()

    # Initialize tinybpf with custom libbpf path if specified
    if args.libbpf:
        bindings.init(libbpf_path=args.libbpf)

    # Create tracker
    tracker = ProcessTracker(
        bpf_path=args.bpf,
        show_forks=not args.no_forks,
        show_exits=not args.no_exits,
        filter_comm=args.filter,
        verbose=args.verbose,
    )

    # Handle signals
    def signal_handler(sig, frame):
        tracker.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

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
