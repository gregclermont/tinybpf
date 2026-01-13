"""
tinybpf - A minimal Python library for loading pre-compiled CO-RE eBPF programs.

This library provides a Pythonic interface to libbpf for loading and
interacting with pre-compiled eBPF programs. It does not compile eBPF
programs - that should be done separately with clang.

Example:
    >>> import tinybpf
    >>>
    >>> with tinybpf.load("program.bpf.o") as obj:
    ...     # Attach a program to a kernel probe
    ...     prog = obj.program("trace_connect")
    ...     link = prog.attach_kprobe("tcp_v4_connect")
    ...
    ...     # Read from a map
    ...     for key, value in obj.maps["connections"].items():
    ...         print(f"Key: {key.hex()}, Value: {value.hex()}")
    ...
    ... # Resources are automatically cleaned up when exiting the context

For typed map access:
    >>> typed_map = obj.maps["counters"].typed(key_format="I", value_format="Q")
    >>> typed_map[0] = 100
    >>> print(typed_map[0])  # 100
"""

from tinybpf.enums import MapType, MapUpdateFlags, ProgramType
from tinybpf.exceptions import (
    BPFAttachError,
    BPFError,
    BPFLoadError,
    BPFMapError,
    BPFNotFoundError,
    BPFPermissionError,
    BPFSyscallError,
    BPFVerifierError,
)
from tinybpf.link import BPFLink
from tinybpf.map import BPFMap, BPFMapCollection, MapInfo, TypedBPFMap
from tinybpf.object import BPFObject, load
from tinybpf.program import BPFProgram

__version__ = "0.1.0"
__all__ = [
    # Main entry point
    "load",
    # Core classes
    "BPFObject",
    "BPFProgram",
    "BPFMap",
    "BPFLink",
    # Map utilities
    "BPFMapCollection",
    "TypedBPFMap",
    "MapInfo",
    # Enums
    "MapType",
    "MapUpdateFlags",
    "ProgramType",
    # Exceptions
    "BPFError",
    "BPFLoadError",
    "BPFVerifierError",
    "BPFAttachError",
    "BPFMapError",
    "BPFNotFoundError",
    "BPFPermissionError",
    "BPFSyscallError",
]
