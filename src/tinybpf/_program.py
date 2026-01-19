"""BPF program loading and attachment.

This module provides the BpfProgram class for attaching BPF programs
to various kernel hook points (kprobes, tracepoints, uprobes, etc.).
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

from tinybpf._libbpf import bindings
from tinybpf._link import BpfLink
from tinybpf._types import BpfError, BpfProgType, ProgramInfo, _check_ptr

if TYPE_CHECKING:
    from pathlib import Path

    from tinybpf._object import BpfObject


class BpfProgram:
    """A BPF program within a loaded object.

    Provides methods to attach the program to various hook points.
    """

    def __init__(self, prog_ptr: Any, obj: BpfObject) -> None:
        self._ptr = prog_ptr
        self._obj = obj  # Keep reference to prevent GC
        lib = bindings._get_lib()
        self._name = lib.bpf_program__name(prog_ptr).decode("utf-8")
        self._section = lib.bpf_program__section_name(prog_ptr).decode("utf-8")
        self._type = BpfProgType(lib.bpf_program__type(prog_ptr))

    def __repr__(self) -> str:
        return f"<BpfProgram '{self._name}' type={self._type.name}>"

    def _check_open(self) -> None:
        """Raise if parent BpfObject is closed."""
        if self._obj._closed:
            raise BpfError("Cannot use program after BpfObject is closed")

    @property
    def name(self) -> str:
        """Return the program name."""
        return self._name

    @property
    def section(self) -> str:
        """Return the ELF section name."""
        return self._section

    @property
    def type(self) -> BpfProgType:
        """Return the program type."""
        return self._type

    @property
    def fd(self) -> int:
        """Return the program file descriptor."""
        self._check_open()
        lib = bindings._get_lib()
        return lib.bpf_program__fd(self._ptr)

    @property
    def info(self) -> ProgramInfo:
        """Return program information as a dataclass."""
        return ProgramInfo(name=self._name, section=self._section, type=self._type)

    def attach(self) -> BpfLink:
        """Auto-attach based on program type and section name.

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach(self._ptr)
        _check_ptr(link, f"attach program '{self._name}'")
        return BpfLink(link, f"auto-attach {self._name}")

    def attach_kprobe(self, func_name: str, retprobe: bool = False) -> BpfLink:
        """Attach to a kprobe or kretprobe.

        Args:
            func_name: Kernel function name to probe.
            retprobe: If True, attach to function return instead of entry.

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_kprobe(self._ptr, retprobe, func_name.encode("utf-8"))
        _check_ptr(link, f"attach kprobe to '{func_name}'")
        kind = "kretprobe" if retprobe else "kprobe"
        return BpfLink(link, f"{kind}:{func_name}")

    def attach_kretprobe(self, func_name: str) -> BpfLink:
        """Attach to a kretprobe (function return).

        Args:
            func_name: Kernel function name to probe.

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
        """
        return self.attach_kprobe(func_name, retprobe=True)

    def attach_tracepoint(self, category: str, name: str) -> BpfLink:
        """Attach to a kernel tracepoint.

        Args:
            category: Tracepoint category (e.g., "syscalls", "sched").
            name: Tracepoint name (e.g., "sys_enter_openat").

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_tracepoint(
            self._ptr, category.encode("utf-8"), name.encode("utf-8")
        )
        _check_ptr(link, f"attach tracepoint to '{category}/{name}'")
        return BpfLink(link, f"tracepoint:{category}/{name}")

    def attach_raw_tracepoint(self, name: str) -> BpfLink:
        """Attach to a raw tracepoint.

        Args:
            name: Raw tracepoint name.

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_raw_tracepoint(self._ptr, name.encode("utf-8"))
        _check_ptr(link, f"attach raw tracepoint to '{name}'")
        return BpfLink(link, f"raw_tracepoint:{name}")

    def attach_uprobe(
        self,
        binary_path: str | Path,
        offset: int = 0,
        pid: int = -1,
        retprobe: bool = False,
    ) -> BpfLink:
        """Attach to a uprobe or uretprobe.

        Args:
            binary_path: Path to the binary/library to probe.
            offset: Offset within the binary to probe.
            pid: Process ID to attach to (-1 for all processes).
            retprobe: If True, attach to function return instead of entry.

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
        """
        self._check_open()
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_uprobe(
            self._ptr, retprobe, pid, str(binary_path).encode("utf-8"), offset
        )
        _check_ptr(link, f"attach uprobe to '{binary_path}+{offset}'")
        kind = "uretprobe" if retprobe else "uprobe"
        return BpfLink(link, f"{kind}:{binary_path}+{offset}")

    def attach_uretprobe(self, binary_path: str | Path, offset: int = 0, pid: int = -1) -> BpfLink:
        """Attach to a uretprobe (function return).

        Args:
            binary_path: Path to the binary/library to probe.
            offset: Offset within the binary to probe.
            pid: Process ID to attach to (-1 for all processes).

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
        """
        return self.attach_uprobe(binary_path, offset, pid, retprobe=True)

    def attach_xdp(self, interface: str | int) -> BpfLink:
        """Attach XDP program to a network interface.

        Args:
            interface: Network interface name (e.g., "eth0") or index.

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
            OSError: If interface name cannot be resolved.
        """
        self._check_open()
        if isinstance(interface, str):
            ifindex = socket.if_nametoindex(interface)
            description = f"xdp:{interface}"
        else:
            ifindex = interface
            description = f"xdp:if{ifindex}"
        lib = bindings._get_lib()
        link = lib.bpf_program__attach_xdp(self._ptr, ifindex)
        _check_ptr(link, f"attach XDP to interface {interface}")
        return BpfLink(link, description)

    def attach_cgroup(self, cgroup: str | Path | int) -> BpfLink:
        """Attach cgroup program to a cgroup.

        Attaches CGROUP_SKB, CGROUP_SOCK, CGROUP_DEVICE, or other cgroup
        program types. The specific attach type is determined by the program's
        section name (e.g., "cgroup_skb/ingress", "cgroup/sock_create").

        Uses multi-attach mode, allowing multiple programs to be attached
        to the same cgroup. Programs run in attachment order; for filtering
        programs, the packet is dropped if any program drops it.

        Args:
            cgroup: Cgroup path (e.g., "/sys/fs/cgroup/user.slice/myapp")
                    or an open file descriptor.

        Returns:
            A BpfLink that must be stored or used as a context manager.
            If discarded, the program will be detached when garbage collected.

        Raises:
            BpfError: If attachment fails.
            FileNotFoundError: If cgroup path does not exist.
        """
        self._check_open()
        lib = bindings._get_lib()

        if isinstance(cgroup, int):
            # User provided fd directly
            link = lib.bpf_program__attach_cgroup(self._ptr, cgroup)
            _check_ptr(link, f"attach cgroup to fd {cgroup}")
            return BpfLink(link, f"cgroup:fd{cgroup}")
        else:
            # Open the cgroup path, attach, then close
            cgroup_path = str(cgroup)
            cgroup_fd = os.open(cgroup_path, os.O_RDONLY)
            try:
                link = lib.bpf_program__attach_cgroup(self._ptr, cgroup_fd)
                _check_ptr(link, f"attach cgroup to '{cgroup_path}'")
                return BpfLink(link, f"cgroup:{cgroup_path}")
            finally:
                os.close(cgroup_fd)


class ProgramCollection(Mapping[str, BpfProgram]):
    """Collection of BPF programs in an object, accessible by name."""

    def __init__(self, progs: dict[str, BpfProgram]) -> None:
        self._progs = progs

    def __getitem__(self, name: str) -> BpfProgram:
        return self._progs[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._progs)

    def __len__(self) -> int:
        return len(self._progs)

    def __repr__(self) -> str:
        return f"<ProgramCollection {list(self._progs.keys())}>"
