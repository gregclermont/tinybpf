"""High-level eBPF object loading and manipulation.

This module provides Pythonic wrappers around libbpf for loading and
interacting with pre-compiled CO-RE eBPF programs.

Example:
    with tinybpf.load("program.bpf.o") as obj:
        obj.program("trace_connect").attach_kprobe("tcp_v4_connect")
        for key, value in obj.maps["connections"].items():
            ...
"""

from __future__ import annotations

import ctypes
import errno
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generic,
    Iterator,
    Mapping,
    TypeVar,
    Union,
    overload,
)

from tinybpf._libbpf import bindings

if TYPE_CHECKING:
    from types import TracebackType


class BpfError(Exception):
    """Base exception for BPF-related errors."""

    def __init__(self, message: str, errno: int = 0) -> None:
        self.errno = errno
        super().__init__(message)


class BpfMapType(IntEnum):
    """BPF map types (subset of commonly used types)."""

    UNSPEC = 0
    HASH = 1
    ARRAY = 2
    PROG_ARRAY = 3
    PERF_EVENT_ARRAY = 4
    PERCPU_HASH = 5
    PERCPU_ARRAY = 6
    STACK_TRACE = 7
    CGROUP_ARRAY = 8
    LRU_HASH = 9
    LRU_PERCPU_HASH = 10
    LPM_TRIE = 11
    ARRAY_OF_MAPS = 12
    HASH_OF_MAPS = 13
    DEVMAP = 14
    SOCKMAP = 15
    CPUMAP = 16
    XSKMAP = 17
    SOCKHASH = 18
    CGROUP_STORAGE = 19
    REUSEPORT_SOCKARRAY = 20
    PERCPU_CGROUP_STORAGE = 21
    QUEUE = 22
    STACK = 23
    SK_STORAGE = 24
    DEVMAP_HASH = 25
    STRUCT_OPS = 26
    RINGBUF = 27
    INODE_STORAGE = 28
    TASK_STORAGE = 29
    BLOOM_FILTER = 30
    USER_RINGBUF = 31
    CGRP_STORAGE = 32


class BpfProgType(IntEnum):
    """BPF program types (subset of commonly used types)."""

    UNSPEC = 0
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4
    TRACEPOINT = 5
    XDP = 6
    PERF_EVENT = 7
    CGROUP_SKB = 8
    CGROUP_SOCK = 9
    LWT_IN = 10
    LWT_OUT = 11
    LWT_XMIT = 12
    SOCK_OPS = 13
    SK_SKB = 14
    CGROUP_DEVICE = 15
    SK_MSG = 16
    RAW_TRACEPOINT = 17
    CGROUP_SOCK_ADDR = 18
    LWT_SEG6LOCAL = 19
    LIRC_MODE2 = 20
    SK_REUSEPORT = 21
    FLOW_DISSECTOR = 22
    CGROUP_SYSCTL = 23
    RAW_TRACEPOINT_WRITABLE = 24
    CGROUP_SOCKOPT = 25
    TRACING = 26
    STRUCT_OPS = 27
    EXT = 28
    LSM = 29
    SK_LOOKUP = 30
    SYSCALL = 31


# Map update flags
BPF_ANY = 0  # Create new or update existing
BPF_NOEXIST = 1  # Create new only if it doesn't exist
BPF_EXIST = 2  # Update existing only


@dataclass(frozen=True)
class MapInfo:
    """Information about a BPF map."""

    name: str
    type: BpfMapType
    key_size: int
    value_size: int
    max_entries: int


@dataclass(frozen=True)
class ProgramInfo:
    """Information about a BPF program."""

    name: str
    section: str
    type: BpfProgType


def _check_ptr(ptr: Any, operation: str) -> None:
    """Check if a libbpf pointer return value indicates an error."""
    lib = bindings._get_lib()
    err = lib.libbpf_get_error(ptr)
    if err != 0:
        err_abs = abs(int(err))
        msg = bindings.libbpf_strerror(err_abs)
        raise BpfError(f"{operation} failed: {msg}", errno=err_abs)


def _check_err(ret: int, operation: str) -> None:
    """Check if a libbpf return value indicates an error.

    Note: libbpf functions return -errno directly (not -1 with errno set),
    so we use abs(ret) to get the error code.
    """
    if ret < 0:
        err_abs = abs(ret)
        msg = bindings.libbpf_strerror(err_abs)
        raise BpfError(f"{operation} failed: {msg}", errno=err_abs)


class BpfLink:
    """A link attaching a BPF program to a hook point.

    Links are automatically destroyed when closed or garbage collected.
    Use as a context manager for automatic cleanup.
    """

    def __init__(self, link_ptr: bindings.bpf_link_p, description: str = "") -> None:
        self._ptr = link_ptr
        self._description = description
        self._destroyed = False

    def __enter__(self) -> BpfLink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.destroy()

    def __del__(self) -> None:
        if not self._destroyed:
            self.destroy()

    def __repr__(self) -> str:
        status = "destroyed" if self._destroyed else f"fd={self.fd}"
        desc = f" ({self._description})" if self._description else ""
        return f"<BpfLink {status}{desc}>"

    @property
    def fd(self) -> int:
        """Return the file descriptor for this link."""
        if self._destroyed:
            return -1
        lib = bindings._get_lib()
        return lib.bpf_link__fd(self._ptr)

    def destroy(self) -> None:
        """Destroy the link, detaching the program."""
        if self._destroyed:
            return
        lib = bindings._get_lib()
        lib.bpf_link__destroy(self._ptr)
        self._destroyed = True


class BpfRingBuffer:
    """Ring buffer consumer for BPF programs.

    Ring buffers (BPF_MAP_TYPE_RINGBUF, kernel 5.8+) are the modern
    replacement for perf buffers, offering better performance and simpler
    usage with a single shared buffer across all CPUs.

    Supports consuming from multiple ring buffer maps with a single poll().

    Example (single map):
        def handle_event(data: bytes) -> int:
            print(f"Got {len(data)} bytes")
            return 0  # Continue polling

        with tinybpf.load("trace.bpf.o") as obj:
            with obj.program("trace").attach():
                with BpfRingBuffer(obj.map("events"), handle_event) as rb:
                    rb.poll(timeout_ms=1000)

    Example (multiple maps):
        rb = BpfRingBuffer()
        rb.add(obj.map("events1"), callback1)
        rb.add(obj.map("events2"), callback2)
        rb.poll()  # Polls all maps with single epoll
    """

    def __init__(
        self,
        map: "BpfMap[Any, Any] | None" = None,
        callback: Callable[[bytes], int] | None = None,
    ) -> None:
        """Create ring buffer consumer.

        Args:
            map: Optional ring buffer map. If provided, callback must also
                 be provided.
            callback: Optional callback for the map's events. Return 0 to
                     continue polling, non-zero to stop.

        Raises:
            ValueError: If only one of map/callback is provided.
        """
        # Set _closed early so __del__ works if __init__ raises
        self._closed = True

        if (map is None) != (callback is None):
            raise ValueError("map and callback must both be provided or both omitted")

        self._ptr: Any = None  # Lazy init on first add()
        self._maps: list[BpfMap[Any, Any]] = []
        self._objs: set[BpfObject] = set()  # All parent objects for use-after-close
        self._callbacks: list[Any] = []  # Keep ctypes callbacks alive
        self._stored_exception: BaseException | None = None

        self._closed = False

        if map is not None:
            self.add(map, callback)  # type: ignore[arg-type]

    def add(
        self,
        map: "BpfMap[Any, Any]",
        callback: Callable[[bytes], int],
    ) -> None:
        """Add a ring buffer map to this consumer.

        Args:
            map: Ring buffer map (must be BPF_MAP_TYPE_RINGBUF).
            callback: Called with event data bytes. Return 0 to continue
                     polling, non-zero to stop.

        Raises:
            BpfError: If ring buffer is closed, map type is wrong,
                     map already added, or libbpf call fails.
        """
        self._check_open()

        if map.type != BpfMapType.RINGBUF:
            raise BpfError(
                f"Map '{map.name}' is type {map.type.name}, expected RINGBUF"
            )

        if map in self._maps:
            raise BpfError(f"Map '{map.name}' already added to this ring buffer")

        # Create ctypes callback wrapper that catches exceptions
        def _callback_wrapper(ctx: Any, data: Any, size: int) -> int:
            try:
                event_data = ctypes.string_at(data, size)
                return callback(event_data)
            except BaseException as e:
                self._stored_exception = e
                return -1  # Stop polling

        cb = bindings.RING_BUFFER_SAMPLE_FN(_callback_wrapper)
        lib = bindings._get_lib()

        if self._ptr is None:
            # First map: create ring buffer
            self._ptr = lib.ring_buffer__new(map.fd, cb, None, None)
            _check_ptr(self._ptr, "ring_buffer__new")
        else:
            # Additional maps: add to existing ring buffer
            ret = lib.ring_buffer__add(self._ptr, map.fd, cb, None)
            _check_err(ret, "ring_buffer__add")

        # Track for lifecycle management
        self._maps.append(map)
        self._objs.add(map._obj)
        self._callbacks.append(cb)

    def _check_open(self) -> None:
        """Raise if ring buffer is closed or any parent BpfObject is closed."""
        if self._closed:
            raise BpfError("Ring buffer is closed")
        for obj in self._objs:
            if obj._closed:
                raise BpfError("Cannot use ring buffer after BpfObject is closed")

    def _check_and_reraise(self) -> None:
        """Re-raise any exception stored from callback."""
        if self._stored_exception is not None:
            exc = self._stored_exception
            self._stored_exception = None
            raise exc

    def poll(self, timeout_ms: int = -1) -> int:
        """Poll for events.

        Waits for events and calls the callback for each one received.

        Args:
            timeout_ms: Timeout in milliseconds. -1 for infinite wait,
                       0 for non-blocking.

        Returns:
            Number of events consumed.

        Raises:
            BpfError: On system error or if no maps have been added.
            Any exception raised by the callbacks.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")
        lib = bindings._get_lib()
        ret = lib.ring_buffer__poll(self._ptr, timeout_ms)
        self._check_and_reraise()
        _check_err(ret, "ring_buffer__poll")
        return ret

    def consume(self) -> int:
        """Consume all available events without waiting.

        Processes all events currently in the ring buffer without blocking.

        Returns:
            Number of events consumed.

        Raises:
            BpfError: On system error or if no maps have been added.
            Any exception raised by the callbacks.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")
        lib = bindings._get_lib()
        ret = lib.ring_buffer__consume(self._ptr)
        self._check_and_reraise()
        _check_err(ret, "ring_buffer__consume")
        return ret

    def close(self) -> None:
        """Close ring buffer and free resources."""
        if not self._closed:
            if self._ptr is not None:
                lib = bindings._get_lib()
                lib.ring_buffer__free(self._ptr)
            self._closed = True

    def __enter__(self) -> "BpfRingBuffer":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: "TracebackType | None",
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            self.close()

    def __repr__(self) -> str:
        status = "closed" if self._closed else "open"
        if len(self._maps) == 0:
            return f"<BpfRingBuffer (no maps) {status}>"
        elif len(self._maps) == 1:
            return f"<BpfRingBuffer map='{self._maps[0].name}' {status}>"
        else:
            names = ", ".join(f"'{m.name}'" for m in self._maps)
            return f"<BpfRingBuffer maps=[{names}] {status}>"


class BpfPerfBuffer:
    """Perf buffer consumer for BPF programs.

    Perf buffers (BPF_MAP_TYPE_PERF_EVENT_ARRAY) are available on kernel 4.4+
    and provide per-CPU event buffers with lost event tracking.

    Example:
        def handle_event(cpu: int, data: bytes) -> None:
            print(f"CPU {cpu}: {len(data)} bytes")

        def handle_lost(cpu: int, count: int) -> None:
            print(f"CPU {cpu}: lost {count} events")

        with tinybpf.load("trace.bpf.o") as obj:
            with obj.program("trace").attach():
                with BpfPerfBuffer(obj.map("events"), handle_event, handle_lost) as pb:
                    pb.poll(timeout_ms=1000)
    """

    def __init__(
        self,
        map: "BpfMap[Any, Any]",
        sample_callback: Callable[[int, bytes], None],
        lost_callback: Callable[[int, int], None] | None = None,
        page_count: int = 8,
    ) -> None:
        """Create perf buffer consumer.

        Args:
            map: Perf event array map (must be BPF_MAP_TYPE_PERF_EVENT_ARRAY).
            sample_callback: Called with (cpu, data) for each event.
            lost_callback: Called with (cpu, lost_count) when events are dropped.
                          If None, lost events are silently ignored.
            page_count: Per-CPU buffer size in pages (must be power of 2).

        Raises:
            BpfError: If map is not a perf event array type.
            ValueError: If page_count is not a power of 2.
        """
        # Set _closed early so __del__ works if __init__ raises
        self._closed = True

        if map.type != BpfMapType.PERF_EVENT_ARRAY:
            raise BpfError(
                f"Map '{map.name}' is type {map.type.name}, expected PERF_EVENT_ARRAY"
            )

        if page_count <= 0 or (page_count & (page_count - 1)) != 0:
            raise ValueError(f"page_count must be a power of 2, got {page_count}")

        self._map = map
        self._obj = map._obj  # For use-after-close detection
        self._user_sample_callback = sample_callback
        self._user_lost_callback = lost_callback
        self._stored_exception: BaseException | None = None

        # Create ctypes callback wrappers
        def _sample_wrapper(ctx: Any, cpu: int, data: Any, size: int) -> None:
            try:
                event_data = ctypes.string_at(data, size)
                self._user_sample_callback(cpu, event_data)
            except BaseException as e:
                self._stored_exception = e

        def _lost_wrapper(ctx: Any, cpu: int, lost_cnt: int) -> None:
            if self._user_lost_callback is not None:
                try:
                    self._user_lost_callback(cpu, lost_cnt)
                except BaseException as e:
                    if self._stored_exception is None:
                        self._stored_exception = e

        # Keep references to prevent garbage collection
        self._sample_cb = bindings.PERF_BUFFER_SAMPLE_FN(_sample_wrapper)
        self._lost_cb = bindings.PERF_BUFFER_LOST_FN(_lost_wrapper)

        lib = bindings._get_lib()
        self._ptr = lib.perf_buffer__new(
            map.fd, page_count, self._sample_cb, self._lost_cb, None, None
        )
        _check_ptr(self._ptr, "perf_buffer__new")

        # Mark as open only after successful initialization
        self._closed = False

    def _check_open(self) -> None:
        """Raise if parent BpfObject is closed or perf buffer is closed."""
        if self._closed:
            raise BpfError("Perf buffer is closed")
        if self._obj._closed:
            raise BpfError("Cannot use perf buffer after BpfObject is closed")

    def _check_and_reraise(self) -> None:
        """Re-raise any exception stored from callback."""
        if self._stored_exception is not None:
            exc = self._stored_exception
            self._stored_exception = None
            raise exc

    def poll(self, timeout_ms: int = -1) -> int:
        """Poll for events from all CPUs.

        Args:
            timeout_ms: Timeout in milliseconds. -1 for infinite wait,
                       0 for non-blocking.

        Returns:
            Number of events consumed.

        Raises:
            BpfError: On system error.
            Any exception raised by the callbacks.
        """
        self._check_open()
        lib = bindings._get_lib()
        ret = lib.perf_buffer__poll(self._ptr, timeout_ms)
        self._check_and_reraise()
        _check_err(ret, "perf_buffer__poll")
        return ret

    def consume(self) -> int:
        """Consume all available events without waiting.

        Returns:
            Number of events consumed.

        Raises:
            BpfError: On system error.
            Any exception raised by the callbacks.
        """
        self._check_open()
        lib = bindings._get_lib()
        ret = lib.perf_buffer__consume(self._ptr)
        self._check_and_reraise()
        _check_err(ret, "perf_buffer__consume")
        return ret

    def close(self) -> None:
        """Close perf buffer and free resources."""
        if not self._closed:
            lib = bindings._get_lib()
            lib.perf_buffer__free(self._ptr)
            self._closed = True

    def __enter__(self) -> "BpfPerfBuffer":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: "TracebackType | None",
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            self.close()

    def __repr__(self) -> str:
        status = "closed" if self._closed else "open"
        return f"<BpfPerfBuffer map='{self._map.name}' {status}>"


class BpfProgram:
    """A BPF program within a loaded object.

    Provides methods to attach the program to various hook points.
    """

    def __init__(self, prog_ptr: bindings.bpf_program_p, obj: BpfObject) -> None:
        self._ptr = prog_ptr
        self._obj = obj  # Keep reference to prevent GC
        lib = bindings._get_lib()
        self._name = lib.bpf_program__name(prog_ptr).decode("utf-8")
        self._section = lib.bpf_program__section_name(prog_ptr).decode("utf-8")
        self._type = BpfProgType(lib.bpf_program__type(prog_ptr))

    def __repr__(self) -> str:
        return f"<BpfProgram '{self._name}' type={self._type.name}>"

    def _check_open(self) -> None:
        """Raise if parent BpfObject is closed."""
        if self._obj._closed:
            raise BpfError("Cannot use program after BpfObject is closed")

    @property
    def name(self) -> str:
        """Return the program name."""
        return self._name

    @property
    def section(self) -> str:
        """Return the ELF section name."""
        return self._section

    @property
    def type(self) -> BpfProgType:
        """Return the program type."""
        return self._type

    @property
    def fd(self) -> int:
        """Return the program file descriptor."""
        self._check_open()
        lib = bindings._get_lib()
        return lib.bpf_program__fd(self._ptr)

    @property
    def info(self) -> ProgramInfo:
        """Return program information as a dataclass."""
        return ProgramInfo(name=self._name, section=self._section, type=self._type)

    def attach(self) -> BpfLink:
        """Auto-attach based on program type and section name.

        Returns:
            A BpfLink that can be used to manage the attachment.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach(self._ptr)
        _check_ptr(link, f"attach program '{self._name}'")
        return BpfLink(link, f"auto-attach {self._name}")

    def attach_kprobe(self, func_name: str, retprobe: bool = False) -> BpfLink:
        """Attach to a kprobe or kretprobe.

        Args:
            func_name: Kernel function name to probe.
            retprobe: If True, attach to function return instead of entry.

        Returns:
            A BpfLink that can be used to manage the attachment.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_kprobe(
            self._ptr, retprobe, func_name.encode("utf-8")
        )
        _check_ptr(link, f"attach kprobe to '{func_name}'")
        kind = "kretprobe" if retprobe else "kprobe"
        return BpfLink(link, f"{kind}:{func_name}")

    def attach_kretprobe(self, func_name: str) -> BpfLink:
        """Attach to a kretprobe (function return).

        Args:
            func_name: Kernel function name to probe.

        Returns:
            A BpfLink that can be used to manage the attachment.

        Raises:
            BpfError: If attachment fails.
        """
        return self.attach_kprobe(func_name, retprobe=True)

    def attach_tracepoint(self, category: str, name: str) -> BpfLink:
        """Attach to a kernel tracepoint.

        Args:
            category: Tracepoint category (e.g., "syscalls", "sched").
            name: Tracepoint name (e.g., "sys_enter_openat").

        Returns:
            A BpfLink that can be used to manage the attachment.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_tracepoint(
            self._ptr, category.encode("utf-8"), name.encode("utf-8")
        )
        _check_ptr(link, f"attach tracepoint to '{category}/{name}'")
        return BpfLink(link, f"tracepoint:{category}/{name}")

    def attach_raw_tracepoint(self, name: str) -> BpfLink:
        """Attach to a raw tracepoint.

        Args:
            name: Raw tracepoint name.

        Returns:
            A BpfLink that can be used to manage the attachment.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_raw_tracepoint(self._ptr, name.encode("utf-8"))
        _check_ptr(link, f"attach raw tracepoint to '{name}'")
        return BpfLink(link, f"raw_tracepoint:{name}")

    def attach_uprobe(
        self,
        binary_path: str | Path,
        offset: int = 0,
        pid: int = -1,
        retprobe: bool = False,
    ) -> BpfLink:
        """Attach to a uprobe or uretprobe.

        Args:
            binary_path: Path to the binary/library to probe.
            offset: Offset within the binary to probe.
            pid: Process ID to attach to (-1 for all processes).
            retprobe: If True, attach to function return instead of entry.

        Returns:
            A BpfLink that can be used to manage the attachment.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_uprobe(
            self._ptr, retprobe, pid, str(binary_path).encode("utf-8"), offset
        )
        _check_ptr(link, f"attach uprobe to '{binary_path}+{offset}'")
        kind = "uretprobe" if retprobe else "uprobe"
        return BpfLink(link, f"{kind}:{binary_path}+{offset}")

    def attach_uretprobe(
        self, binary_path: str | Path, offset: int = 0, pid: int = -1
    ) -> BpfLink:
        """Attach to a uretprobe (function return).

        Args:
            binary_path: Path to the binary/library to probe.
            offset: Offset within the binary to probe.
            pid: Process ID to attach to (-1 for all processes).

        Returns:
            A BpfLink that can be used to manage the attachment.

        Raises:
            BpfError: If attachment fails.
        """
        return self.attach_uprobe(binary_path, offset, pid, retprobe=True)


KT = TypeVar("KT")
VT = TypeVar("VT")


class BpfMap(Generic[KT, VT]):
    """A BPF map within a loaded object.

    Provides dict-like access to map elements and iteration support.
    By default, keys and values are treated as raw bytes.
    """

    def __init__(
        self,
        map_ptr: bindings.bpf_map_p,
        obj: BpfObject,
        key_type: type[KT] | None = None,
        value_type: type[VT] | None = None,
    ) -> None:
        self._ptr = map_ptr
        self._obj = obj  # Keep reference to prevent GC
        lib = bindings._get_lib()
        self._name = lib.bpf_map__name(map_ptr).decode("utf-8")
        self._type = BpfMapType(lib.bpf_map__type(map_ptr))
        self._key_size = lib.bpf_map__key_size(map_ptr)
        self._value_size = lib.bpf_map__value_size(map_ptr)
        self._max_entries = lib.bpf_map__max_entries(map_ptr)
        self._key_type = key_type
        self._value_type = value_type

    def __repr__(self) -> str:
        return (
            f"<BpfMap '{self._name}' type={self._type.name} "
            f"key_size={self._key_size} value_size={self._value_size}>"
        )

    @property
    def name(self) -> str:
        """Return the map name."""
        return self._name

    @property
    def type(self) -> BpfMapType:
        """Return the map type."""
        return self._type

    @property
    def key_size(self) -> int:
        """Return the key size in bytes."""
        return self._key_size

    @property
    def value_size(self) -> int:
        """Return the value size in bytes."""
        return self._value_size

    @property
    def max_entries(self) -> int:
        """Return the maximum number of entries."""
        return self._max_entries

    @property
    def fd(self) -> int:
        """Return the map file descriptor."""
        self._check_open()
        lib = bindings._get_lib()
        return lib.bpf_map__fd(self._ptr)

    @property
    def info(self) -> MapInfo:
        """Return map information as a dataclass."""
        return MapInfo(
            name=self._name,
            type=self._type,
            key_size=self._key_size,
            value_size=self._value_size,
            max_entries=self._max_entries,
        )

    def _check_open(self) -> None:
        """Raise if parent BpfObject is closed."""
        if self._obj._closed:
            raise BpfError("Cannot use map after BpfObject is closed")

    def _to_key_bytes(self, key: KT) -> bytes:
        """Convert key to bytes."""
        if isinstance(key, bytes):
            if len(key) != self._key_size:
                raise ValueError(
                    f"Key size mismatch: got {len(key)}, expected {self._key_size}"
                )
            return key
        if isinstance(key, ctypes.Structure):
            return bytes(key)
        if isinstance(key, int):
            return key.to_bytes(self._key_size, byteorder="little")
        raise TypeError(f"Cannot convert {type(key).__name__} to key bytes")

    def _to_value_bytes(self, value: VT) -> bytes:
        """Convert value to bytes."""
        if isinstance(value, bytes):
            if len(value) != self._value_size:
                raise ValueError(
                    f"Value size mismatch: got {len(value)}, expected {self._value_size}"
                )
            return value
        if isinstance(value, ctypes.Structure):
            return bytes(value)
        if isinstance(value, int):
            return value.to_bytes(self._value_size, byteorder="little")
        raise TypeError(f"Cannot convert {type(value).__name__} to value bytes")

    def _from_key_bytes(self, data: bytes) -> KT:
        """Convert bytes to key type."""
        if self._key_type is None:
            return data  # type: ignore
        if self._key_type is int:
            return int.from_bytes(data, byteorder="little")  # type: ignore
        if issubclass(self._key_type, ctypes.Structure):
            return self._key_type.from_buffer_copy(data)  # type: ignore
        return data  # type: ignore

    def _from_value_bytes(self, data: bytes) -> VT:
        """Convert bytes to value type."""
        if self._value_type is None:
            return data  # type: ignore
        if self._value_type is int:
            return int.from_bytes(data, byteorder="little")  # type: ignore
        if issubclass(self._value_type, ctypes.Structure):
            return self._value_type.from_buffer_copy(data)  # type: ignore
        return data  # type: ignore

    def lookup(self, key: KT) -> VT | None:
        """Look up a value by key.

        Args:
            key: The key to look up (bytes, int, or ctypes.Structure).

        Returns:
            The value if found, None otherwise.
        """
        self._check_open()
        lib = bindings._get_lib()
        key_bytes = self._to_key_bytes(key)
        key_buf = ctypes.create_string_buffer(key_bytes, self._key_size)
        value_buf = ctypes.create_string_buffer(self._value_size)

        ret = lib.bpf_map_lookup_elem(
            self.fd, ctypes.cast(key_buf, ctypes.c_void_p), ctypes.cast(value_buf, ctypes.c_void_p)
        )
        if ret < 0:
            err = abs(ret)
            if err == errno.ENOENT:
                return None  # Key not found - expected, dict-like behavior
            msg = bindings.libbpf_strerror(err)
            raise BpfError(f"Map lookup failed for '{self._name}': {msg}", errno=err)
        return self._from_value_bytes(value_buf.raw)

    def update(
        self, key: KT, value: VT, flags: int = BPF_ANY
    ) -> None:
        """Update a map element.

        Args:
            key: The key to update.
            value: The new value.
            flags: Update flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST).

        Raises:
            BpfError: If update fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        key_bytes = self._to_key_bytes(key)
        value_bytes = self._to_value_bytes(value)
        key_buf = ctypes.create_string_buffer(key_bytes, self._key_size)
        value_buf = ctypes.create_string_buffer(value_bytes, self._value_size)

        ret = lib.bpf_map_update_elem(
            self.fd,
            ctypes.cast(key_buf, ctypes.c_void_p),
            ctypes.cast(value_buf, ctypes.c_void_p),
            flags,
        )
        _check_err(ret, f"update map '{self._name}'")

    def delete(self, key: KT) -> bool:
        """Delete a map element.

        Args:
            key: The key to delete.

        Returns:
            True if element was deleted, False if not found.
        """
        self._check_open()
        lib = bindings._get_lib()
        key_bytes = self._to_key_bytes(key)
        key_buf = ctypes.create_string_buffer(key_bytes, self._key_size)

        ret = lib.bpf_map_delete_elem(self.fd, ctypes.cast(key_buf, ctypes.c_void_p))
        if ret < 0:
            err = abs(ret)
            if err == errno.ENOENT:
                return False  # Key not found
            msg = bindings.libbpf_strerror(err)
            raise BpfError(f"Map delete failed for '{self._name}': {msg}", errno=err)
        return True

    def __getitem__(self, key: KT) -> VT:
        """Get a value by key, raising KeyError if not found."""
        value = self.lookup(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: KT, value: VT) -> None:
        """Set a value by key."""
        self.update(key, value)

    def __delitem__(self, key: KT) -> None:
        """Delete a value by key, raising KeyError if not found."""
        if not self.delete(key):
            raise KeyError(key)

    def __contains__(self, key: KT) -> bool:
        """Check if key exists in map."""
        return self.lookup(key) is not None

    def __iter__(self) -> Iterator[KT]:
        """Iterate over map keys."""
        return self.keys()

    def keys(self) -> Iterator[KT]:
        """Iterate over map keys.

        Yields:
            Each key in the map.
        """
        self._check_open()
        lib = bindings._get_lib()
        prev_key: bytes | None = None
        next_key_buf = ctypes.create_string_buffer(self._key_size)

        while True:
            if prev_key is None:
                prev_key_ptr = None
            else:
                prev_key_buf = ctypes.create_string_buffer(prev_key, self._key_size)
                prev_key_ptr = ctypes.cast(prev_key_buf, ctypes.c_void_p)

            ret = lib.bpf_map_get_next_key(
                self.fd, prev_key_ptr, ctypes.cast(next_key_buf, ctypes.c_void_p)
            )
            if ret < 0:
                err = abs(ret)
                if err == errno.ENOENT:
                    break  # No more keys - normal termination
                msg = bindings.libbpf_strerror(err)
                raise BpfError(
                    f"Map iteration failed for '{self._name}': {msg}", errno=err
                )

            key_bytes = next_key_buf.raw
            yield self._from_key_bytes(key_bytes)
            prev_key = key_bytes

    def values(self) -> Iterator[VT]:
        """Iterate over map values.

        Yields:
            Each value in the map.
        """
        for key in self.keys():
            value = self.lookup(key)
            if value is not None:
                yield value

    def items(self) -> Iterator[tuple[KT, VT]]:
        """Iterate over (key, value) pairs.

        Yields:
            Tuples of (key, value) for each entry.
        """
        for key in self.keys():
            value = self.lookup(key)
            if value is not None:
                yield key, value

    def get(self, key: KT, default: VT | None = None) -> VT | None:
        """Get a value with a default if not found."""
        value = self.lookup(key)
        return value if value is not None else default


class MapCollection(Mapping[str, BpfMap[Any, Any]]):
    """Collection of BPF maps in an object, accessible by name."""

    def __init__(self, maps: dict[str, BpfMap[Any, Any]]) -> None:
        self._maps = maps

    def __getitem__(self, name: str) -> BpfMap[Any, Any]:
        return self._maps[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._maps)

    def __len__(self) -> int:
        return len(self._maps)

    def __repr__(self) -> str:
        return f"<MapCollection {list(self._maps.keys())}>"


class ProgramCollection(Mapping[str, BpfProgram]):
    """Collection of BPF programs in an object, accessible by name."""

    def __init__(self, progs: dict[str, BpfProgram]) -> None:
        self._progs = progs

    def __getitem__(self, name: str) -> BpfProgram:
        return self._progs[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._progs)

    def __len__(self) -> int:
        return len(self._progs)

    def __repr__(self) -> str:
        return f"<ProgramCollection {list(self._progs.keys())}>"


class BpfObject:
    """A loaded BPF object file.

    Use the `load()` function to create instances. BpfObject supports
    the context manager protocol for automatic resource cleanup.

    Example:
        with tinybpf.load("program.bpf.o") as obj:
            print(obj.name)
            for prog in obj.programs.values():
                print(prog.name, prog.type)
    """

    def __init__(self, obj_ptr: bindings.bpf_object_p, path: Path) -> None:
        self._ptr = obj_ptr
        self._path = path
        self._closed = False

        lib = bindings._get_lib()
        name = lib.bpf_object__name(obj_ptr)
        self._name = name.decode("utf-8") if name else path.stem

        # Collect programs
        self._programs: dict[str, BpfProgram] = {}
        prog = lib.bpf_object__next_program(obj_ptr, None)
        while prog:
            bp = BpfProgram(prog, self)
            self._programs[bp.name] = bp
            prog = lib.bpf_object__next_program(obj_ptr, prog)

        # Collect maps
        self._maps: dict[str, BpfMap[Any, Any]] = {}
        map_ = lib.bpf_object__next_map(obj_ptr, None)
        while map_:
            bm: BpfMap[Any, Any] = BpfMap(map_, self)
            self._maps[bm.name] = bm
            map_ = lib.bpf_object__next_map(obj_ptr, map_)

    def __enter__(self) -> BpfObject:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            self.close()

    def __repr__(self) -> str:
        status = "closed" if self._closed else "open"
        return f"<BpfObject '{self._name}' {status} programs={len(self._programs)} maps={len(self._maps)}>"

    @property
    def name(self) -> str:
        """Return the object name."""
        return self._name

    @property
    def path(self) -> Path:
        """Return the path to the object file."""
        return self._path

    @property
    def programs(self) -> ProgramCollection:
        """Return collection of programs in this object."""
        return ProgramCollection(self._programs)

    @property
    def maps(self) -> MapCollection:
        """Return collection of maps in this object."""
        return MapCollection(self._maps)

    def program(self, name: str) -> BpfProgram:
        """Get a program by name.

        Args:
            name: The program name.

        Returns:
            The BpfProgram instance.

        Raises:
            KeyError: If program not found.
        """
        return self._programs[name]

    def map(self, name: str) -> BpfMap[Any, Any]:
        """Get a map by name.

        Args:
            name: The map name.

        Returns:
            The BpfMap instance.

        Raises:
            KeyError: If map not found.
        """
        return self._maps[name]

    def close(self) -> None:
        """Close and release the BPF object resources."""
        if self._closed:
            return
        lib = bindings._get_lib()
        lib.bpf_object__close(self._ptr)
        self._closed = True


def load(path: str | Path) -> BpfObject:
    """Load a BPF object file.

    This opens and loads a pre-compiled CO-RE eBPF object file (.bpf.o).
    The returned object can be used with a context manager for automatic cleanup.

    Args:
        path: Path to the .bpf.o file.

    Returns:
        A BpfObject instance with programs and maps ready to use.

    Raises:
        BpfError: If loading fails.
        FileNotFoundError: If the file doesn't exist.

    Example:
        with tinybpf.load("program.bpf.o") as obj:
            link = obj.program("trace_openat").attach()
            # ... do work ...
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"BPF object file not found: {path}")

    lib = bindings._get_lib()

    # Open the object file
    obj_ptr = lib.bpf_object__open_file(str(path).encode("utf-8"), None)
    _check_ptr(obj_ptr, f"open '{path}'")

    # Load the object into the kernel
    ret = lib.bpf_object__load(obj_ptr)
    if ret < 0:
        lib.bpf_object__close(obj_ptr)
        _check_err(ret, f"load '{path}'")

    return BpfObject(obj_ptr, path)
