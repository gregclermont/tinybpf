"""Tests for BPF program attachment.

Run with: sudo pytest tests/test_programs.py -v
"""

from pathlib import Path

import pytest

import tinybpf
from conftest import requires_root

pytestmark = requires_root


class TestBpfProgramAttachment:
    """Tests for program attachment."""

    def test_attach_tracepoint(self, minimal_bpf_path: Path) -> None:
        """Can attach to a tracepoint."""
        with tinybpf.load(minimal_bpf_path) as obj:
            prog = obj.program("trace_openat")
            link = prog.attach_tracepoint("syscalls", "sys_enter_openat")
            assert link.fd >= 0
            assert "tracepoint" in repr(link)
            link.destroy()
            assert link.fd == -1

    def test_auto_attach(self, minimal_bpf_path: Path) -> None:
        """Auto-attach based on section name."""
        with tinybpf.load(minimal_bpf_path) as obj:
            prog = obj.program("trace_openat")
            link = prog.attach()
            assert link.fd >= 0
            link.destroy()

    def test_link_context_manager(self, minimal_bpf_path: Path) -> None:
        """Link supports context manager protocol."""
        with tinybpf.load(minimal_bpf_path) as obj:
            prog = obj.program("trace_openat")
            with prog.attach() as link:
                assert link.fd >= 0
            # Link should be destroyed after with block
            assert link.fd == -1


class TestKprobeAttachment:
    """Tests for kprobe attachment (requires test_maps.bpf.o with kprobe)."""

    def test_attach_kprobe(self, test_maps_bpf_path: Path) -> None:
        """Can attach to a kprobe."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            if "trace_tcp_connect" not in obj.programs:
                pytest.skip("kprobe program not found in test object")
            prog = obj.program("trace_tcp_connect")
            link = prog.attach_kprobe("tcp_v4_connect")
            assert link.fd >= 0
            assert "kprobe" in repr(link)
            link.destroy()

    def test_attach_kretprobe(self, test_maps_bpf_path: Path) -> None:
        """Can attach to a kretprobe."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            if "trace_tcp_connect" not in obj.programs:
                pytest.skip("kprobe program not found in test object")
            prog = obj.program("trace_tcp_connect")
            link = prog.attach_kretprobe("tcp_v4_connect")
            assert link.fd >= 0
            assert "kretprobe" in repr(link)
            link.destroy()


class TestXdpAttachment:
    """Tests for XDP attachment."""

    def test_attach_xdp_by_index(self, xdp_bpf_path: Path) -> None:
        """Can attach XDP program using interface index."""
        import socket

        with tinybpf.load(xdp_bpf_path) as obj:
            prog = obj.program("xdp_pass")
            ifindex = socket.if_nametoindex("lo")
            link = prog.attach_xdp(ifindex)
            assert link.fd >= 0
            assert "xdp" in repr(link)
            link.destroy()
            assert link.fd == -1

    def test_attach_xdp_by_name(self, xdp_bpf_path: Path) -> None:
        """Can attach XDP program using interface name."""
        with tinybpf.load(xdp_bpf_path) as obj:
            prog = obj.program("xdp_pass")
            link = prog.attach_xdp("lo")
            assert link.fd >= 0
            assert "xdp:lo" in repr(link)
            link.destroy()
            assert link.fd == -1

    def test_attach_xdp_context_manager(self, xdp_bpf_path: Path) -> None:
        """XDP link supports context manager protocol."""
        with tinybpf.load(xdp_bpf_path) as obj:
            prog = obj.program("xdp_pass")
            with prog.attach_xdp("lo") as link:
                assert link.fd >= 0
            assert link.fd == -1

    def test_attach_xdp_invalid_interface(self, xdp_bpf_path: Path) -> None:
        """Attaching to non-existent interface raises OSError."""
        with tinybpf.load(xdp_bpf_path) as obj:
            prog = obj.program("xdp_pass")
            with pytest.raises(OSError):
                prog.attach_xdp("nonexistent_interface_xyz")


class TestCgroupAttachment:
    """Tests for cgroup attachment."""

    def test_attach_cgroup_by_path(self, cgroup_bpf_path: Path, current_cgroup_path: str) -> None:
        """Can attach cgroup program using path."""
        with tinybpf.load(cgroup_bpf_path) as obj:
            prog = obj.program("cgroup_skb_egress")
            link = prog.attach_cgroup(current_cgroup_path)
            assert link.fd >= 0
            assert "cgroup:" in repr(link)
            assert current_cgroup_path in repr(link)
            link.destroy()
            assert link.fd == -1

    def test_attach_cgroup_by_fd(self, cgroup_bpf_path: Path, current_cgroup_path: str) -> None:
        """Can attach cgroup program using file descriptor."""
        import os

        with tinybpf.load(cgroup_bpf_path) as obj:
            prog = obj.program("cgroup_skb_egress")
            cgroup_fd = os.open(current_cgroup_path, os.O_RDONLY)
            try:
                link = prog.attach_cgroup(cgroup_fd)
                assert link.fd >= 0
                assert "cgroup:fd" in repr(link)
                link.destroy()
                assert link.fd == -1
            finally:
                os.close(cgroup_fd)

    def test_attach_cgroup_context_manager(
        self, cgroup_bpf_path: Path, current_cgroup_path: str
    ) -> None:
        """Cgroup link supports context manager protocol."""
        with tinybpf.load(cgroup_bpf_path) as obj:
            prog = obj.program("cgroup_skb_egress")
            with prog.attach_cgroup(current_cgroup_path) as link:
                assert link.fd >= 0
            assert link.fd == -1

    def test_attach_cgroup_invalid_path(self, cgroup_bpf_path: Path) -> None:
        """Attaching to non-existent cgroup path raises FileNotFoundError."""
        with tinybpf.load(cgroup_bpf_path) as obj:
            prog = obj.program("cgroup_skb_egress")
            with pytest.raises(FileNotFoundError):
                prog.attach_cgroup("/sys/fs/cgroup/nonexistent_cgroup_xyz")


class TestProgramAttachmentErrors:
    """Tests for program attachment error handling."""

    def test_attach_nonexistent_function(self, minimal_bpf_path: Path) -> None:
        """Attaching to non-existent kernel function should raise BpfError."""
        with tinybpf.load(minimal_bpf_path) as obj:
            prog = obj.programs["trace_openat"]
            with pytest.raises(tinybpf.BpfError):
                prog.attach_kprobe("this_function_does_not_exist_xyz123")
