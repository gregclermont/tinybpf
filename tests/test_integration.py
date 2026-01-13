"""
Integration tests for tinybpf.

These tests require:
- Root privileges or CAP_BPF capability
- A compiled BPF program (minimal.bpf.o)
- libbpf installed or bundled

Run with: sudo pytest tests/test_integration.py -v
"""

import os
import struct
import time
from pathlib import Path

import pytest

# Skip all tests in this module if not root
pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="Integration tests require root privileges",
)


def get_bpf_program_path() -> Path:
    """Get the path to the compiled test BPF program."""
    # Try several locations
    locations = [
        Path(__file__).parent.parent / "bpf" / "minimal.bpf.o",
        Path("bpf/minimal.bpf.o"),
        Path("/tmp/minimal.bpf.o"),
    ]
    for path in locations:
        if path.exists():
            return path
    pytest.skip("Compiled BPF program not found")


@pytest.fixture
def bpf_program_path() -> Path:
    """Fixture providing path to compiled BPF program."""
    return get_bpf_program_path()


class TestBPFObjectLoading:
    """Tests for loading BPF objects."""

    def test_load_object(self, bpf_program_path: Path) -> None:
        """Test loading a BPF object file."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            assert obj.is_loaded
            assert obj.name  # Should have a name

    def test_context_manager_cleanup(self, bpf_program_path: Path) -> None:
        """Test that context manager properly cleans up."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            assert obj.is_loaded

        assert not obj.is_loaded

    def test_list_programs(self, bpf_program_path: Path) -> None:
        """Test listing programs in an object."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            program_names = obj.program_names()
            assert len(program_names) > 0
            assert "trace_nanosleep" in program_names or "trace_sys_nanosleep" in program_names

    def test_list_maps(self, bpf_program_path: Path) -> None:
        """Test listing maps in an object."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            map_names = obj.map_names()
            assert len(map_names) > 0
            assert "counter" in map_names or "test_hash" in map_names


class TestBPFProgram:
    """Tests for BPF program operations."""

    def test_get_program_by_name(self, bpf_program_path: Path) -> None:
        """Test getting a program by name."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            prog = obj.program("trace_nanosleep")
            assert prog.name == "trace_nanosleep"
            assert prog.fd > 0

    def test_program_properties(self, bpf_program_path: Path) -> None:
        """Test program properties."""
        import tinybpf
        from tinybpf.enums import ProgramType

        with tinybpf.load(bpf_program_path) as obj:
            prog = obj.program("trace_nanosleep")
            assert prog.section_name  # Should have a section name
            assert prog.type == ProgramType.KPROBE

    def test_attach_kprobe(self, bpf_program_path: Path) -> None:
        """Test attaching a kprobe."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            prog = obj.program("trace_nanosleep")
            link = prog.attach_kprobe("do_nanosleep")

            assert link.is_attached
            assert link.program is prog

            link.detach()
            assert not link.is_attached

    def test_attach_tracepoint(self, bpf_program_path: Path) -> None:
        """Test attaching a tracepoint."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            prog = obj.program("trace_sys_nanosleep")
            link = prog.attach_tracepoint("syscalls", "sys_enter_nanosleep")

            assert link.is_attached
            link.detach()


class TestBPFMap:
    """Tests for BPF map operations."""

    def test_get_map_by_name(self, bpf_program_path: Path) -> None:
        """Test getting a map by name."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            counter = obj.maps["counter"]
            assert counter.name == "counter"
            assert counter.fd > 0

    def test_map_properties(self, bpf_program_path: Path) -> None:
        """Test map properties."""
        import tinybpf
        from tinybpf.enums import MapType

        with tinybpf.load(bpf_program_path) as obj:
            counter = obj.maps["counter"]
            assert counter.type == MapType.ARRAY
            assert counter.key_size == 4
            assert counter.value_size == 8
            assert counter.max_entries == 1

    def test_map_info(self, bpf_program_path: Path) -> None:
        """Test MapInfo dataclass."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            counter = obj.maps["counter"]
            info = counter.info

            assert info.name == "counter"
            assert info.key_size == 4
            assert info.value_size == 8

    def test_array_map_update_lookup(self, bpf_program_path: Path) -> None:
        """Test updating and looking up values in an array map."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            counter = obj.maps["counter"]

            # Set initial value
            key = struct.pack("I", 0)
            value = struct.pack("Q", 42)
            counter.update(key, value)

            # Read back
            result = counter.lookup(key)
            assert result is not None
            assert struct.unpack("Q", result)[0] == 42

    def test_hash_map_operations(self, bpf_program_path: Path) -> None:
        """Test hash map operations."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            test_hash = obj.maps["test_hash"]

            # Insert a value
            key = struct.pack("I", 12345)
            value = struct.pack("Q", 67890)
            test_hash.update(key, value)

            # Lookup
            result = test_hash.lookup(key)
            assert result is not None
            assert struct.unpack("Q", result)[0] == 67890

            # Delete
            test_hash.delete(key)
            assert test_hash.lookup(key) is None

    def test_map_iteration(self, bpf_program_path: Path) -> None:
        """Test iterating over map entries."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            test_hash = obj.maps["test_hash"]

            # Clear the map first
            test_hash.clear()

            # Insert some values
            for i in range(5):
                key = struct.pack("I", i)
                value = struct.pack("Q", i * 100)
                test_hash.update(key, value)

            # Iterate
            count = 0
            for key, value in test_hash.items():
                count += 1
                k = struct.unpack("I", key)[0]
                v = struct.unpack("Q", value)[0]
                assert v == k * 100

            assert count == 5

    def test_typed_map(self, bpf_program_path: Path) -> None:
        """Test TypedBPFMap wrapper."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            counter = obj.maps["counter"]
            typed = counter.typed(key_format="I", value_format="Q")

            # Set value using typed interface
            typed[0] = 999

            # Read back
            assert typed[0] == 999

            # Test iteration
            for key in typed:
                assert isinstance(key, int)


class TestBPFLink:
    """Tests for BPF link operations."""

    def test_link_context_manager(self, bpf_program_path: Path) -> None:
        """Test using link as context manager."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            prog = obj.program("trace_nanosleep")

            with prog.attach_kprobe("do_nanosleep") as link:
                assert link.is_attached

            assert not link.is_attached

    def test_detach_all(self, bpf_program_path: Path) -> None:
        """Test detaching all links from a program."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            prog = obj.program("trace_nanosleep")

            link1 = prog.attach_kprobe("do_nanosleep")
            # Can't attach same program to same hook twice,
            # so just test with one link

            assert len(prog.links) == 1
            prog.detach_all()
            assert len(prog.links) == 0


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_trace_nanosleep(self, bpf_program_path: Path) -> None:
        """Test tracing nanosleep calls."""
        import tinybpf

        with tinybpf.load(bpf_program_path) as obj:
            prog = obj.program("trace_nanosleep")
            counter = obj.maps["counter"].typed(key_format="I", value_format="Q")

            # Reset counter
            counter[0] = 0

            # Attach
            link = prog.attach_kprobe("do_nanosleep")

            # Trigger some nanosleep calls
            for _ in range(3):
                time.sleep(0.001)  # 1ms sleep

            # Check counter was incremented
            # Note: might be more than 3 due to other processes
            assert counter[0] >= 3

            link.detach()
