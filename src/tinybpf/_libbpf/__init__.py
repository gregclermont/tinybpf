"""
Internal libbpf bindings using ctypes.

This module loads the bundled libbpf shared library and provides
low-level ctypes bindings to the libbpf C API.
"""

from tinybpf._libbpf.bindings import (
    LibBPF,
    get_libbpf,
)

__all__ = ["LibBPF", "get_libbpf"]
