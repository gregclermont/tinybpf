"""tinybpf - Minimal Python library for loading CO-RE eBPF programs.

Example:
    >>> import tinybpf
    >>> with tinybpf.load("program.bpf.o") as obj:
    ...     obj.program("trace_connect").attach_kprobe("tcp_v4_connect")
    ...     for key, value in obj.maps["connections"].items():
    ...         print(key, value)
"""

__version__ = "0.0.1"

from tinybpf._libbpf import init, libbpf_version
from tinybpf._object import (
    BPF_ANY,
    BPF_EXIST,
    BPF_NOEXIST,
    BpfError,
    BpfLink,
    BpfMap,
    BpfMapType,
    BpfObject,
    BpfProgram,
    BpfProgType,
    MapCollection,
    MapInfo,
    ProgramCollection,
    ProgramInfo,
    load,
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
    # Classes
    "BpfObject",
    "BpfProgram",
    "BpfMap",
    "BpfLink",
    # Collections
    "MapCollection",
    "ProgramCollection",
    # Data classes
    "MapInfo",
    "ProgramInfo",
    # Enums
    "BpfMapType",
    "BpfProgType",
    # Exceptions
    "BpfError",
    # Constants
    "BPF_ANY",
    "BPF_NOEXIST",
    "BPF_EXIST",
]
