"""BPF types, enums, dataclasses, and error handling.

This module contains foundational types used throughout tinybpf:
- BpfError exception
- BtfValidationError exception for BTF type mismatches
- BpfMapType, BpfProgType, and BtfKind enums
- MapInfo, ProgramInfo, RingBufferEvent, BtfType, BtfField dataclasses
- Map update flag constants
- Error checking helper functions
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Generic, TypeVar

from tinybpf._libbpf import bindings

T = TypeVar("T")


class BpfError(Exception):
    """Base exception for BPF-related errors.

    Attributes:
        errno: The error number from the failed operation (0 if not applicable).
        libbpf_log: Detailed output from libbpf (verifier log, CO-RE errors, etc.)
            that provides more context than the basic error message.
    """

    def __init__(self, message: str, errno: int = 0, libbpf_log: str | None = None) -> None:
        self.errno = errno
        self.libbpf_log = libbpf_log
        # Include log excerpt in message if available
        if libbpf_log:
            message = f"{message}\n\nlibbpf output:\n{libbpf_log}"
        super().__init__(message)


class BtfValidationError(BpfError):
    """Exception for BTF type validation failures.

    Raised when a Python type doesn't match the expected BTF type metadata.
    The suggestions list may contain struct names from BTF to help users
    find the correct type name.
    """

    def __init__(self, message: str, suggestions: list[str] | None = None) -> None:
        self.suggestions = suggestions or []
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


class BtfKind(IntEnum):
    """BTF type kinds.

    Defines the various BTF type kinds used for type introspection.
    """

    UNKN = 0
    INT = 1
    PTR = 2
    ARRAY = 3
    STRUCT = 4
    UNION = 5
    ENUM = 6
    FWD = 7
    TYPEDEF = 8
    VOLATILE = 9
    CONST = 10
    RESTRICT = 11
    FUNC = 12
    FUNC_PROTO = 13
    VAR = 14
    DATASEC = 15
    FLOAT = 16
    DECL_TAG = 17
    TYPE_TAG = 18
    ENUM64 = 19


# Map update flags
BPF_ANY = 0  # Create new or update existing
BPF_NOEXIST = 1  # Create new only if it doesn't exist
BPF_EXIST = 2  # Update existing only

# BPF object name length (from kernel)
BPF_OBJ_NAME_LEN = 16


class _BpfMapInfoKernel(ctypes.Structure):
    """Kernel bpf_map_info structure for bpf_obj_get_info_by_fd.

    This is a subset of the full struct - only fields we need.
    The kernel will fill in what it knows and ignore extra space.
    """

    _fields_ = [  # noqa: RUF012 (required by ctypes.Structure)
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("name", ctypes.c_char * BPF_OBJ_NAME_LEN),
        # Additional fields exist but aren't needed for basic functionality
    ]


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


@dataclass(frozen=True)
class RingBufferEvent(Generic[T]):
    """Event from a ring buffer with source map information.

    Used with BpfRingBuffer.events() for multi-map ring buffers where
    you need to identify which map each event came from.

    The data field is typed according to the event_type parameter
    passed to BpfRingBuffer (defaults to bytes).
    """

    map_name: str
    data: T


@dataclass(frozen=True)
class BtfField:
    """Information about a field in a BTF struct or union.

    Attributes:
        name: Field name.
        offset: Offset from start of struct in bytes.
        size: Size of the field in bytes.
    """

    name: str
    offset: int  # bytes
    size: int


@dataclass(frozen=True)
class BtfType:
    """BTF type information.

    Describes a type from BTF metadata including its name, kind, size,
    and for structs/unions, its fields.

    Attributes:
        name: Type name (e.g., "unsigned int", "event").
        kind: The BTF kind (INT, STRUCT, etc.).
        size: Size in bytes (None for pointer types, typedefs).
        fields: Tuple of BtfField for STRUCT/UNION, None for other kinds.
    """

    name: str
    kind: BtfKind
    size: int | None
    fields: tuple[BtfField, ...] | None = None


def btf_kind(info: int) -> int:
    """Extract BTF kind from info field."""
    return (info >> 24) & 0x1F


def btf_vlen(info: int) -> int:
    """Extract vlen (variable length) from BTF info field.

    For STRUCT/UNION, this is the number of members.
    For ENUM, this is the number of enumerators.
    """
    return info & 0xFFFF


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


def _from_event_bytes(data: bytes, event_type: type[T], *, strict_size: bool = True) -> T:
    """Convert bytes to event type (ctypes.Structure or bytes passthrough).

    Args:
        data: Raw event bytes from ring buffer or perf buffer.
        event_type: Target type (bytes or a ctypes.Structure subclass).
        strict_size: If True, require exact size match (used for ring buffers).
            If False, allow extra trailing bytes but require them to be zeros
            (used for perf buffers which have kernel-added padding).

    Returns:
        Event data converted to the specified type.

    Raises:
        BpfError: If size validation fails:
            - Data smaller than expected type size
            - strict_size=True and data size doesn't match exactly
            - strict_size=False and extra trailing bytes are non-zero

    Note:
        Perf buffers (BPF_MAP_TYPE_PERF_EVENT_ARRAY) pad data to 64-bit alignment
        with zeros. If you receive non-zero trailing bytes, this likely indicates
        a struct size mismatch. If you encounter a kernel bug causing non-zero
        garbage bytes, use event_type=bytes as a workaround.
    """
    if event_type is bytes:
        return data  # type: ignore[return-value]
    # ctypes.Structure - cast to Any to access from_buffer_copy
    struct_type: Any = event_type
    expected_size = ctypes.sizeof(struct_type)
    if len(data) < expected_size:
        raise BpfError(
            f"Event size mismatch: received {len(data)} bytes, "
            f"expected {expected_size} for {struct_type.__name__}"
        )
    if strict_size and len(data) != expected_size:
        raise BpfError(
            f"Event size mismatch: received {len(data)} bytes, "
            f"expected exactly {expected_size} for {struct_type.__name__}"
        )
    if not strict_size and len(data) > expected_size:
        # Perf buffer padding should be zeros; non-zero indicates mismatch
        trailing = data[expected_size:]
        if any(b != 0 for b in trailing):
            raise BpfError(
                f"Event size mismatch: received {len(data)} bytes with non-zero "
                f"trailing data, expected {expected_size} for {struct_type.__name__}. "
                f"This likely indicates your Python struct doesn't match the BPF struct."
            )
    # from_buffer_copy uses only the first expected_size bytes
    return struct_type.from_buffer_copy(data)
