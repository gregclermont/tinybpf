"""
BPF program management.

This module provides the BPFProgram class for working with individual
BPF programs within a loaded object.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tinybpf._libbpf import get_libbpf
from tinybpf._libbpf.bindings import bpf_program_p
from tinybpf.enums import ProgramType
from tinybpf.link import BPFLink

if TYPE_CHECKING:
    from tinybpf.object import BPFObject


class BPFProgram:
    """
    Represents a single BPF program within a loaded BPF object.

    BPFProgram instances are created by BPFObject and should not be
    instantiated directly. Use obj.program("name") or obj.programs
    to access programs.

    Example:
        >>> with tinybpf.load("program.bpf.o") as obj:
        ...     prog = obj.program("trace_connect")
        ...     link = prog.attach_kprobe("tcp_v4_connect")
        ...     # Program is now attached and tracing tcp_v4_connect
    """

    def __init__(
        self,
        prog_ptr: bpf_program_p,
        obj: BPFObject,
    ) -> None:
        """
        Initialize a BPFProgram.

        This should not be called directly. Use BPFObject.program()
        to get program instances.

        Args:
            prog_ptr: Pointer to the underlying bpf_program structure.
            obj: The parent BPFObject.
        """
        self._ptr = prog_ptr
        self._obj = obj
        self._libbpf = get_libbpf()
        self._links: list[BPFLink] = []

    @property
    def name(self) -> str:
        """The name of this program (typically the C function name)."""
        return self._libbpf.program_name(self._ptr)

    @property
    def section_name(self) -> str:
        """
        The ELF section name of this program.

        This typically indicates the program type and attachment point,
        e.g., "kprobe/tcp_v4_connect" or "tracepoint/syscalls/sys_enter_read".
        """
        return self._libbpf.program_section_name(self._ptr)

    @property
    def fd(self) -> int:
        """
        File descriptor for this loaded program.

        Returns -1 if the program is not loaded.
        """
        return self._libbpf.program_fd(self._ptr)

    @property
    def type(self) -> ProgramType:
        """The BPF program type."""
        return ProgramType(self._libbpf.program_type(self._ptr))

    @property
    def links(self) -> list[BPFLink]:
        """List of active links (attachments) for this program."""
        # Filter out destroyed links
        self._links = [link for link in self._links if link.is_attached]
        return list(self._links)

    def _register_link(self, link: BPFLink) -> BPFLink:
        """Register a link for lifecycle management."""
        self._links.append(link)
        return link

    def attach(self) -> BPFLink:
        """
        Auto-attach based on the program's section name.

        This uses libbpf's automatic attachment logic based on
        the ELF section name (e.g., "kprobe/func_name" will attach
        as a kprobe to func_name).

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.
        """
        link_ptr = self._libbpf.attach_program(self._ptr)
        link = BPFLink(link_ptr, self, f"auto:{self.section_name}")
        return self._register_link(link)

    def attach_kprobe(self, func_name: str) -> BPFLink:
        """
        Attach this program to a kernel function entry point.

        Args:
            func_name: Name of the kernel function to trace.

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.

        Example:
            >>> link = prog.attach_kprobe("tcp_v4_connect")
        """
        link_ptr = self._libbpf.attach_kprobe(self._ptr, func_name, retprobe=False)
        link = BPFLink(link_ptr, self, f"kprobe:{func_name}")
        return self._register_link(link)

    def attach_kretprobe(self, func_name: str) -> BPFLink:
        """
        Attach this program to a kernel function return point.

        Args:
            func_name: Name of the kernel function to trace.

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.

        Example:
            >>> link = prog.attach_kretprobe("tcp_v4_connect")
        """
        link_ptr = self._libbpf.attach_kprobe(self._ptr, func_name, retprobe=True)
        link = BPFLink(link_ptr, self, f"kretprobe:{func_name}")
        return self._register_link(link)

    def attach_tracepoint(self, category: str, name: str) -> BPFLink:
        """
        Attach this program to a kernel tracepoint.

        Args:
            category: Tracepoint category (e.g., "syscalls", "sched").
            name: Tracepoint name (e.g., "sys_enter_read", "sched_switch").

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.

        Example:
            >>> link = prog.attach_tracepoint("syscalls", "sys_enter_read")
        """
        link_ptr = self._libbpf.attach_tracepoint(self._ptr, category, name)
        link = BPFLink(link_ptr, self, f"tracepoint:{category}/{name}")
        return self._register_link(link)

    def attach_uprobe(
        self,
        binary_path: str,
        func_offset: int,
        pid: int = -1,
    ) -> BPFLink:
        """
        Attach this program to a userspace function entry point.

        Args:
            binary_path: Path to the binary or shared library.
            func_offset: Offset of the function within the binary.
            pid: Process ID to trace (-1 for all processes).

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.

        Example:
            >>> link = prog.attach_uprobe("/lib/x86_64-linux-gnu/libc.so.6", 0x12345)
        """
        link_ptr = self._libbpf.attach_uprobe(
            self._ptr, binary_path, func_offset, pid, retprobe=False
        )
        link = BPFLink(link_ptr, self, f"uprobe:{binary_path}+{func_offset:#x}")
        return self._register_link(link)

    def attach_uretprobe(
        self,
        binary_path: str,
        func_offset: int,
        pid: int = -1,
    ) -> BPFLink:
        """
        Attach this program to a userspace function return point.

        Args:
            binary_path: Path to the binary or shared library.
            func_offset: Offset of the function within the binary.
            pid: Process ID to trace (-1 for all processes).

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.

        Example:
            >>> link = prog.attach_uretprobe("/lib/x86_64-linux-gnu/libc.so.6", 0x12345)
        """
        link_ptr = self._libbpf.attach_uprobe(
            self._ptr, binary_path, func_offset, pid, retprobe=True
        )
        link = BPFLink(link_ptr, self, f"uretprobe:{binary_path}+{func_offset:#x}")
        return self._register_link(link)

    def attach_raw_tracepoint(self, tp_name: str) -> BPFLink:
        """
        Attach this program to a raw tracepoint.

        Raw tracepoints provide lower-level access to tracepoint data
        without the overhead of the regular tracepoint infrastructure.

        Args:
            tp_name: Name of the raw tracepoint.

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.

        Example:
            >>> link = prog.attach_raw_tracepoint("sys_enter")
        """
        link_ptr = self._libbpf.attach_raw_tracepoint(self._ptr, tp_name)
        link = BPFLink(link_ptr, self, f"raw_tp:{tp_name}")
        return self._register_link(link)

    def attach_perf_event(self, perf_fd: int) -> BPFLink:
        """
        Attach this program to a perf event file descriptor.

        This is a low-level interface for attaching to custom perf events.

        Args:
            perf_fd: File descriptor of an open perf event.

        Returns:
            A BPFLink representing the attachment.

        Raises:
            BPFAttachError: If attachment fails.
        """
        link_ptr = self._libbpf.attach_perf_event(self._ptr, perf_fd)
        link = BPFLink(link_ptr, self, f"perf_event:fd={perf_fd}")
        return self._register_link(link)

    def detach_all(self) -> None:
        """Detach all active links for this program."""
        for link in self._links:
            if link.is_attached:
                link.detach()
        self._links.clear()

    def __repr__(self) -> str:
        return f"BPFProgram({self.name!r}, type={self.type.name})"
