"""tinybpf - Minimal Python library for loading CO-RE eBPF programs."""

__version__ = "0.0.1"

from tinybpf._libbpf import init, libbpf_version


def version() -> str:
    """Return the tinybpf package version."""
    return __version__


__all__ = ["version", "init", "libbpf_version"]
