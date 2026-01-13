"""
BPF link management.

This module provides the BPFLink class for managing attachments between
BPF programs and kernel hooks.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from tinybpf._libbpf import get_libbpf
from tinybpf._libbpf.bindings import bpf_link_p
from tinybpf.exceptions import BPFError

if TYPE_CHECKING:
    from tinybpf.program import BPFProgram


class BPFLink:
    """
    Represents an attachment between a BPF program and a kernel hook.

    Links are created by attaching programs to hooks (kprobes, tracepoints,
    etc.). When a link is destroyed, the program is detached from the hook.

    BPFLink instances should typically be managed through the context manager
    protocol or by letting the parent BPFObject manage their lifecycle.

    Example:
        >>> link = program.attach_kprobe("tcp_v4_connect")
        >>> # Program is now attached
        >>> link.detach()
        >>> # Program is now detached
    """

    def __init__(
        self,
        link_ptr: bpf_link_p,
        program: BPFProgram,
        hook_name: str,
    ) -> None:
        """
        Initialize a BPFLink.

        This should not be called directly. Use program.attach_* methods
        to create links.

        Args:
            link_ptr: Pointer to the underlying bpf_link structure.
            program: The program this link is for.
            hook_name: Human-readable description of the hook.
        """
        self._ptr = link_ptr
        self._program = program
        self._hook_name = hook_name
        self._destroyed = False
        self._pin_path: Path | None = None
        self._libbpf = get_libbpf()

    @property
    def program(self) -> BPFProgram:
        """The program this link attaches."""
        return self._program

    @property
    def hook_name(self) -> str:
        """Human-readable description of the attachment hook."""
        return self._hook_name

    @property
    def fd(self) -> int:
        """
        File descriptor for this link.

        Returns -1 if the link has been destroyed.
        """
        if self._destroyed:
            return -1
        return self._libbpf.link_fd(self._ptr)

    @property
    def is_attached(self) -> bool:
        """Whether this link is currently attached."""
        return not self._destroyed

    @property
    def pin_path(self) -> Path | None:
        """Path where this link is pinned, if any."""
        return self._pin_path

    def detach(self) -> None:
        """
        Detach the program and destroy this link.

        This is safe to call multiple times. After calling detach(),
        the link can no longer be used.
        """
        if self._destroyed:
            return

        try:
            self._libbpf.link_destroy(self._ptr)
        finally:
            self._destroyed = True
            self._pin_path = None

    def pin(self, path: str | Path) -> None:
        """
        Pin this link to the BPF filesystem.

        Pinning allows the link to persist after the process exits.
        The link can be recovered by opening the pinned file.

        Args:
            path: Path in the BPF filesystem (typically under /sys/fs/bpf/).

        Raises:
            BPFError: If pinning fails or link is destroyed.
        """
        if self._destroyed:
            raise BPFError("Cannot pin destroyed link")

        path = Path(path)
        self._libbpf.link_pin(self._ptr, str(path))
        self._pin_path = path

    def unpin(self) -> None:
        """
        Unpin this link from the BPF filesystem.

        Raises:
            BPFError: If unpinning fails or link is not pinned.
        """
        if self._destroyed:
            raise BPFError("Cannot unpin destroyed link")
        if self._pin_path is None:
            raise BPFError("Link is not pinned")

        self._libbpf.link_unpin(self._ptr)
        self._pin_path = None

    def __enter__(self) -> BPFLink:
        """Context manager entry - returns self."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Context manager exit - detaches the link."""
        self.detach()

    def __repr__(self) -> str:
        status = "attached" if self.is_attached else "detached"
        return f"BPFLink({self._program.name!r} -> {self._hook_name!r}, {status})"

    def __del__(self) -> None:
        """Destructor - ensures link is properly destroyed."""
        if not self._destroyed:
            try:
                self.detach()
            except Exception:
                pass  # Ignore errors during cleanup
