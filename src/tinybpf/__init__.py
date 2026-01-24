"""tinybpf - Minimal Python library for loading CO-RE eBPF programs.

Example:
    >>> import tinybpf
    >>> with tinybpf.load("program.bpf.o") as obj:
    ...     obj.program("trace_connect").attach_kprobe("tcp_v4_connect")
    ...     for key, value in obj.maps["connections"].items():
    ...         print(key, value)
"""

__version__ = "0.2.2"

from tinybpf._buffers import BpfPerfBuffer, BpfRingBuffer
from tinybpf._libbpf import init, libbpf_version
from tinybpf._link import BpfLink
from tinybpf._map import BpfMap, MapCollection, open_pinned_map
from tinybpf._object import BpfObject, load
from tinybpf._program import BpfProgram, ProgramCollection
from tinybpf._types import (
    BPF_ANY,
    BPF_EXIST,
    BPF_NOEXIST,
    BpfError,
    BpfMapType,
    BpfProgType,
    BtfField,
    BtfKind,
    BtfType,
    BtfValidationError,
    MapInfo,
    ProgramInfo,
    RingBufferEvent,
)


def version() -> str:
    """Return the tinybpf package version."""
    return __version__


__all__ = [
    # Version functions
    "version",
    "init",
    "libbpf_version",
    # Main API
    "load",
    "open_pinned_map",
    # Classes
    "BpfObject",
    "BpfProgram",
    "BpfMap",
    "BpfLink",
    "BpfPerfBuffer",
    "BpfRingBuffer",
    # Collections
    "MapCollection",
    "ProgramCollection",
    # Data classes
    "MapInfo",
    "ProgramInfo",
    "RingBufferEvent",
    "BtfType",
    "BtfField",
    # Enums
    "BpfMapType",
    "BpfProgType",
    "BtfKind",
    # Exceptions
    "BpfError",
    "BtfValidationError",
    # Constants
    "BPF_ANY",
    "BPF_NOEXIST",
    "BPF_EXIST",
]
