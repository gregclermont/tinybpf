"""
Custom exceptions for tinybpf.

This module provides a hierarchy of exceptions for different error
conditions that can occur when working with BPF programs and maps.
"""

from __future__ import annotations

import os


class BPFError(Exception):
    """Base exception for all tinybpf errors."""

    pass


class BPFLoadError(BPFError):
    """Error loading a BPF object file."""

    pass


class BPFVerifierError(BPFLoadError):
    """BPF program failed kernel verifier."""

    def __init__(self, message: str, verifier_log: str | None = None) -> None:
        super().__init__(message)
        self.verifier_log = verifier_log


class BPFAttachError(BPFError):
    """Error attaching a BPF program to a hook."""

    pass


class BPFMapError(BPFError):
    """Error performing a map operation."""

    pass


class BPFNotFoundError(BPFError):
    """Requested BPF program or map was not found."""

    pass


class BPFPermissionError(BPFError):
    """Insufficient permissions for BPF operation."""

    def __init__(self, message: str | None = None) -> None:
        if message is None:
            message = (
                "Insufficient permissions for BPF operation. "
                "Try running as root or with CAP_BPF capability."
            )
        super().__init__(message)


class BPFSyscallError(BPFError):
    """Low-level BPF syscall failed."""

    def __init__(self, message: str, errno_val: int) -> None:
        self.errno = errno_val
        self.strerror = os.strerror(errno_val)
        super().__init__(f"{message}: {self.strerror} (errno={errno_val})")
