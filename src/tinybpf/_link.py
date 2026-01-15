"""BPF link management.

A BpfLink represents an attachment of a BPF program to a hook point
(kprobe, tracepoint, etc.). Links are automatically destroyed when
closed or garbage collected.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tinybpf._libbpf import bindings

if TYPE_CHECKING:
    from types import TracebackType


class BpfLink:
    """A link attaching a BPF program to a hook point.

    Links are automatically destroyed when closed or garbage collected.
    Use as a context manager for automatic cleanup.
    """

    def __init__(self, link_ptr: Any, description: str = "") -> None:
        self._ptr = link_ptr
        self._description = description
        self._destroyed = False

    def __enter__(self) -> BpfLink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.destroy()

    def __del__(self) -> None:
        if not self._destroyed:
            self.destroy()

    def __repr__(self) -> str:
        status = "destroyed" if self._destroyed else f"fd={self.fd}"
        desc = f" ({self._description})" if self._description else ""
        return f"<BpfLink {status}{desc}>"

    @property
    def fd(self) -> int:
        """Return the file descriptor for this link."""
        if self._destroyed:
            return -1
        lib = bindings._get_lib()
        return lib.bpf_link__fd(self._ptr)

    def destroy(self) -> None:
        """Destroy the link, detaching the program."""
        if self._destroyed:
            return
        lib = bindings._get_lib()
        lib.bpf_link__destroy(self._ptr)
        self._destroyed = True
