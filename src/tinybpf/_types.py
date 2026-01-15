"""BPF types, enums, dataclasses, and error handling.

This module contains foundational types used throughout tinybpf:
- BpfError exception
- BpfMapType and BpfProgType enums
- MapInfo, ProgramInfo, RingBufferEvent dataclasses
- Map update flag constants
- Error checking helper functions
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from tinybpf._libbpf import bindings


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
class RingBufferEvent:
    """Event from a ring buffer with source map information.

    Used with BpfRingBuffer.events() for multi-map ring buffers where
    you need to identify which map each event came from.
    """

    map_name: str
    data: bytes


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
