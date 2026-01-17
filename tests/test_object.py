"""Tests for BpfObject loading and lifecycle.

Run with: sudo pytest tests/test_object.py -v
"""

from pathlib import Path

import pytest

import tinybpf
from conftest import requires_root

pytestmark = requires_root


class TestBpfObjectLoading:
    """Tests for BpfObject loading."""

    def test_load_minimal(self, minimal_bpf_path: Path) -> None:
        """Can load a minimal BPF object."""
        with tinybpf.load(minimal_bpf_path) as obj:
            # libbpf extracts the object name from ELF metadata (without .bpf suffix)
            assert obj.name == "minimal"
            assert obj.path == minimal_bpf_path
            assert len(obj.programs) >= 1

    def test_context_manager_cleanup(self, minimal_bpf_path: Path) -> None:
        """Context manager properly cleans up resources."""
        obj = tinybpf.load(minimal_bpf_path)
        obj_repr = repr(obj)
        assert "open" in obj_repr
        assert "programs=" in obj_repr
        obj.close()
        assert "closed" in repr(obj)

    def test_programs_accessible(self, minimal_bpf_path: Path) -> None:
        """Programs are accessible by name."""
        with tinybpf.load(minimal_bpf_path) as obj:
            assert "trace_openat" in obj.programs
            prog = obj.program("trace_openat")
            assert prog.name == "trace_openat"
            assert prog.type == tinybpf.BpfProgType.TRACEPOINT
            assert prog.fd >= 0

    def test_program_info(self, minimal_bpf_path: Path) -> None:
        """ProgramInfo dataclass contains correct data."""
        with tinybpf.load(minimal_bpf_path) as obj:
            prog = obj.program("trace_openat")
            info = prog.info
            assert info.name == "trace_openat"
            assert info.type == tinybpf.BpfProgType.TRACEPOINT
            assert "tracepoint" in info.section.lower()


class TestBpfObjectErrors:
    """Tests for BpfObject error handling."""

    def test_program_use_after_close(self, minimal_bpf_path: Path) -> None:
        """Using program after BpfObject.close() should raise BpfError."""
        obj = tinybpf.load(minimal_bpf_path)
        prog = obj.programs["trace_openat"]
        obj.close()

        with pytest.raises(tinybpf.BpfError, match="closed"):
            prog.attach()

    def test_load_failure_includes_libbpf_output(self, core_fail_bpf_path: Path) -> None:
        """BpfError should include libbpf's detailed output on load failure."""
        with pytest.raises(tinybpf.BpfError) as exc_info:
            tinybpf.load(core_fail_bpf_path)

        error = exc_info.value
        # Should have errno set
        assert error.errno != 0
        # Should have libbpf_log with detailed error info
        assert error.libbpf_log is not None
        assert "CO-RE" in error.libbpf_log or "relocation" in error.libbpf_log
        # The full message should include the libbpf output
        assert "libbpf output:" in str(error)
