"""Internal libbpf bindings."""

from tinybpf._libbpf.bindings import init, libbpf_version

__all__ = ["init", "libbpf_version"]
