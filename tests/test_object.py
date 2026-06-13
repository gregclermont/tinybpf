"""Tests for BpfObject loading and lifecycle.

Run with: sudo pytest tests/test_object.py -v
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import tinybpf
from conftest import requires_root

pytestmark = requires_root


# NOTE: The capture_libbpf_output deadlock regression test below does NOT
# require root. It lives in this module (which is otherwise root-gated via the
# module-level pytestmark) because the test files in scope are limited; it is
# run in a subprocess with a hard timeout so a regression manifests as a
# timeout/failure rather than hanging the whole suite. It is therefore subject
# to the module skipif when run unprivileged, but the underlying logic it
# exercises needs no privileges.


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


class TestBpfObjectMaps:
    """Tests for BpfObject.map()."""

    def test_map_returns_same_instance_as_maps(self, test_maps_bpf_path: Path) -> None:
        """obj.map(name) returns the same BpfMap instance as obj.maps[name]."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            m = obj.map("pid_counts")
            assert m.name == "pid_counts"
            # Should be the identical instance backing the maps collection.
            assert m is obj.maps["pid_counts"]

    def test_map_multiple_names(self, test_maps_bpf_path: Path) -> None:
        """All declared maps are reachable via map()."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            for name in ("pid_counts", "counters", "percpu_stats"):
                assert obj.map(name).name == name

    def test_map_not_found_raises_keyerror_with_available(self, test_maps_bpf_path: Path) -> None:
        """Unknown map name raises KeyError listing available maps."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            with pytest.raises(KeyError) as exc_info:
                obj.map("does_not_exist")
            # KeyError stringifies its arg with repr; check the helpful message.
            message = str(exc_info.value)
            assert "does_not_exist" in message
            assert "pid_counts" in message


class TestCaptureLibbpfOutput:
    """Regression tests for capture_libbpf_output()."""

    def test_capture_does_not_deadlock_on_large_output(self) -> None:
        """Writing more than a pipe buffer (~64KB) to stderr inside the body
        must not deadlock, and the output must be fully captured.

        Before the fix, the pipe was only drained after the body returned, so a
        writer that filled the ~64KB pipe buffer blocked forever inside the
        body. We run in a subprocess with a timeout so a regression fails fast
        instead of hanging the suite.
        """
        # ~512KB, far larger than any pipe buffer.
        payload_size = 512 * 1024
        script = textwrap.dedent(f"""
            import os, sys
            from tinybpf._libbpf import bindings
            data = b"x" * {payload_size}
            with bindings.capture_libbpf_output():
                os.write(2, data)
            out = bindings.get_captured_output()
            assert len(out) == {payload_size}, len(out)
            # stderr must be restored to the real fd 2 afterwards.
            os.write(2, b"")
            sys.stdout.write("OK")
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ},
            check=False,
        )
        assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
        assert result.stdout == "OK", result.stdout


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
        # The fixture provokes a CO-RE relocation against a field that may or
        # may not exist depending on the running kernel's BTF (e.g. whether the
        # tracepoint uses an inline array). On kernels where the relocation
        # resolves, the load succeeds and there is no failure path to exercise.
        try:
            obj = tinybpf.load(core_fail_bpf_path)
        except tinybpf.BpfError as exc:
            error = exc
        else:
            obj.close()
            pytest.skip("kernel BTF satisfies the CO-RE relocation; no load failure to inspect")

        # Should have errno set
        assert error.errno != 0
        # Should have libbpf_log with detailed error info
        assert error.libbpf_log is not None
        assert "CO-RE" in error.libbpf_log or "relocation" in error.libbpf_log
        # The full message should include the libbpf output
        assert "libbpf output:" in str(error)
