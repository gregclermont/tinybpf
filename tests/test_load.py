"""Integration tests for loading eBPF programs.

These tests require:
- Root privileges (CAP_BPF, CAP_SYS_ADMIN)
- Pre-compiled .bpf.o files in tests/bpf/
- A kernel with BPF support

Run with: sudo pytest tests/test_load.py -v
"""

import os
from pathlib import Path

import pytest

import tinybpf

# Skip all tests in this module if not root
pytestmark = pytest.mark.skipif(
    os.geteuid() != 0, reason="Root privileges required for BPF operations"
)

TESTS_DIR = Path(__file__).parent
BPF_DIR = TESTS_DIR / "bpf"


@pytest.fixture
def minimal_bpf_path() -> Path:
    """Path to compiled minimal.bpf.o test program."""
    path = BPF_DIR / "minimal.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path


@pytest.fixture
def test_maps_bpf_path() -> Path:
    """Path to compiled test_maps.bpf.o test program."""
    path = BPF_DIR / "test_maps.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path


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


class TestBpfMaps:
    """Tests for BPF map operations."""

    def test_maps_accessible(self, test_maps_bpf_path: Path) -> None:
        """Maps are accessible by name."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            assert "pid_counts" in obj.maps
            assert "counters" in obj.maps
            assert "percpu_stats" in obj.maps

    def test_map_info(self, test_maps_bpf_path: Path) -> None:
        """MapInfo dataclass contains correct data."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            assert hash_map.type == tinybpf.BpfMapType.HASH
            assert hash_map.key_size == 4  # __u32
            assert hash_map.value_size == 8  # __u64
            assert hash_map.max_entries == 1024

            array_map = obj.map("counters")
            assert array_map.type == tinybpf.BpfMapType.ARRAY
            assert array_map.max_entries == 16

    def test_map_update_and_lookup(self, test_maps_bpf_path: Path) -> None:
        """Can update and lookup map elements."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")

            # Use integer keys/values (converted to bytes)
            key = 12345
            value = 42

            # Update
            hash_map.update(
                key.to_bytes(4, "little"), value.to_bytes(8, "little")
            )

            # Lookup
            result = hash_map.lookup(key.to_bytes(4, "little"))
            assert result is not None
            assert int.from_bytes(result, "little") == 42

            # Delete
            assert hash_map.delete(key.to_bytes(4, "little"))
            assert hash_map.lookup(key.to_bytes(4, "little")) is None

    def test_map_dict_interface(self, test_maps_bpf_path: Path) -> None:
        """Map supports dict-like interface."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            key = (99999).to_bytes(4, "little")
            value = (100).to_bytes(8, "little")

            # __setitem__
            hash_map[key] = value

            # __getitem__
            assert hash_map[key] == value

            # __contains__
            assert key in hash_map

            # __delitem__
            del hash_map[key]
            assert key not in hash_map

            # KeyError on missing
            with pytest.raises(KeyError):
                _ = hash_map[key]

    def test_map_iteration(self, test_maps_bpf_path: Path) -> None:
        """Can iterate over map entries."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")

            # Insert some entries
            for i in range(5):
                key = (1000 + i).to_bytes(4, "little")
                value = (i * 10).to_bytes(8, "little")
                hash_map[key] = value

            # keys()
            keys = list(hash_map.keys())
            assert len(keys) >= 5

            # values()
            values = list(hash_map.values())
            assert len(values) >= 5

            # items()
            items = list(hash_map.items())
            assert len(items) >= 5

            # Clean up
            for i in range(5):
                key = (1000 + i).to_bytes(4, "little")
                hash_map.delete(key)

    def test_array_map_operations(self, test_maps_bpf_path: Path) -> None:
        """Array maps work correctly."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            array_map = obj.map("counters")

            # Arrays have fixed indices
            idx = (0).to_bytes(4, "little")
            value = (12345).to_bytes(8, "little")

            array_map[idx] = value
            assert array_map[idx] == value

            # Array maps always have all keys (can't delete)
            # But we can set to zero
            array_map[idx] = (0).to_bytes(8, "little")


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


class TestErrorPaths:
    """Tests for error handling and edge cases."""

    def test_attach_nonexistent_function(self, minimal_bpf_path: Path) -> None:
        """Attaching to non-existent kernel function should raise BpfError."""
        with tinybpf.load(minimal_bpf_path) as obj:
            prog = obj.programs["trace_openat"]
            with pytest.raises(tinybpf.BpfError):
                prog.attach_kprobe("this_function_does_not_exist_xyz123")

    def test_empty_map_iteration(self, test_maps_bpf_path: Path) -> None:
        """Iterating an empty map should yield nothing."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            # Ensure map is empty (delete any existing keys)
            for key in list(hash_map.keys()):
                hash_map.delete(key)
            # Verify iteration yields nothing
            assert list(hash_map.keys()) == []
            assert list(hash_map.values()) == []
            assert list(hash_map.items()) == []

    def test_map_update_exceeds_max_entries(self, test_maps_bpf_path: Path) -> None:
        """Exceeding map max_entries should raise BpfError."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            max_entries = hash_map.max_entries

            # Fill the map to capacity
            inserted_keys = []
            for i in range(max_entries):
                key = (i + 100000).to_bytes(4, "little")
                value = (i).to_bytes(8, "little")
                hash_map.update(key, value, tinybpf.BPF_NOEXIST)
                inserted_keys.append(key)

            try:
                # Try to insert one more - should fail
                overflow_key = (max_entries + 100000).to_bytes(4, "little")
                with pytest.raises(tinybpf.BpfError):
                    hash_map.update(overflow_key, b"\x00" * 8, tinybpf.BPF_NOEXIST)
            finally:
                # Clean up
                for key in inserted_keys:
                    hash_map.delete(key)

    def test_program_use_after_close(self, minimal_bpf_path: Path) -> None:
        """Using program after BpfObject.close() should raise BpfError."""
        obj = tinybpf.load(minimal_bpf_path)
        prog = obj.programs["trace_openat"]
        obj.close()

        with pytest.raises(tinybpf.BpfError, match="closed"):
            prog.attach()

    def test_map_use_after_close(self, test_maps_bpf_path: Path) -> None:
        """Using map after BpfObject.close() should raise BpfError."""
        obj = tinybpf.load(test_maps_bpf_path)
        hash_map = obj.map("pid_counts")
        obj.close()

        with pytest.raises(tinybpf.BpfError, match="closed"):
            hash_map.lookup(b"\x00" * 4)

    def test_map_iteration_after_close(self, test_maps_bpf_path: Path) -> None:
        """Iterating map after BpfObject.close() should raise BpfError."""
        obj = tinybpf.load(test_maps_bpf_path)
        hash_map = obj.map("pid_counts")
        obj.close()

        with pytest.raises(tinybpf.BpfError, match="closed"):
            list(hash_map.keys())


class TestBpfRingBuffer:
    """Tests for ring buffer operations."""

    @pytest.fixture
    def ringbuf_bpf_path(self) -> Path:
        """Path to compiled test_ringbuf.bpf.o test program."""
        path = BPF_DIR / "test_ringbuf.bpf.o"
        if not path.exists():
            pytest.skip(f"Compiled BPF program not found: {path}")
        return path

    def test_ringbuf_creation(self, ringbuf_bpf_path: Path) -> None:
        """Can create ring buffer from ringbuf map."""
        events: list[bytes] = []

        def callback(data: bytes) -> int:
            events.append(data)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"), callback)
            assert "open" in repr(rb)
            rb.close()
            assert "closed" in repr(rb)

    def test_ringbuf_wrong_map_type(self, test_maps_bpf_path: Path) -> None:
        """Creating ring buffer from non-ringbuf map raises BpfError."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            with pytest.raises(tinybpf.BpfError, match="RINGBUF"):
                tinybpf.BpfRingBuffer(hash_map, lambda d: 0)

    def test_ringbuf_poll_events(self, ringbuf_bpf_path: Path) -> None:
        """Can poll and receive events."""
        import subprocess

        events: list[bytes] = []

        def callback(data: bytes) -> int:
            events.append(data)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            prog = obj.program("trace_execve")
            with prog.attach() as link:
                with tinybpf.BpfRingBuffer(obj.map("events"), callback) as rb:
                    # Trigger execve to generate event
                    subprocess.run(["/bin/true"], check=True)
                    rb.poll(timeout_ms=100)

        assert len(events) >= 1
        # Verify event structure (pid, tid, comm) = 4 + 4 + 16 = 24 bytes
        assert len(events[0]) == 24

    def test_ringbuf_callback_exception(self, ringbuf_bpf_path: Path) -> None:
        """Exception in callback is propagated."""
        import subprocess

        def bad_callback(data: bytes) -> int:
            raise ValueError("test error")

        with tinybpf.load(ringbuf_bpf_path) as obj:
            prog = obj.program("trace_execve")
            with prog.attach() as link:
                with tinybpf.BpfRingBuffer(obj.map("events"), bad_callback) as rb:
                    subprocess.run(["/bin/true"], check=True)
                    with pytest.raises(ValueError, match="test error"):
                        rb.poll(timeout_ms=100)

    def test_ringbuf_use_after_close(self, ringbuf_bpf_path: Path) -> None:
        """Using ring buffer after close raises BpfError."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
            rb.close()
            with pytest.raises(tinybpf.BpfError, match="closed"):
                rb.poll()

    def test_ringbuf_use_after_object_close(self, ringbuf_bpf_path: Path) -> None:
        """Using ring buffer after BpfObject close raises BpfError."""
        obj = tinybpf.load(ringbuf_bpf_path)
        rb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
        obj.close()
        with pytest.raises(tinybpf.BpfError, match="closed"):
            rb.poll()
        rb.close()

    def test_ringbuf_context_manager(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer supports context manager protocol."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            with tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0) as rb:
                assert "open" in repr(rb)
            # Ring buffer should be closed after with block
            assert "closed" in repr(rb)

    def test_ringbuf_empty_constructor(self) -> None:
        """Can create ring buffer with no args."""
        rb = tinybpf.BpfRingBuffer()
        assert "(no maps)" in repr(rb)
        assert "open" in repr(rb)
        rb.close()
        assert "closed" in repr(rb)

    def test_ringbuf_constructor_validation(self, ringbuf_bpf_path: Path) -> None:
        """Callback without map raises ValueError."""
        # Callback without map is invalid
        with pytest.raises(ValueError, match="callback requires map"):
            tinybpf.BpfRingBuffer(callback=lambda d: 0)

    def test_ringbuf_iterator_mode(self, ringbuf_bpf_path: Path) -> None:
        """Map without callback creates iterator mode ring buffer."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"))
            assert "iterator" in repr(rb)
            rb.close()

    def test_ringbuf_poll_without_maps(self) -> None:
        """Poll on empty ring buffer raises BpfError."""
        rb = tinybpf.BpfRingBuffer()
        with pytest.raises(tinybpf.BpfError, match="No maps added"):
            rb.poll()
        rb.close()

    def test_ringbuf_add_map(self, ringbuf_bpf_path: Path) -> None:
        """Can add multiple maps and receive events from both."""
        import subprocess

        events1: list[bytes] = []
        events2: list[bytes] = []

        def callback1(data: bytes) -> int:
            events1.append(data)
            return 0

        def callback2(data: bytes) -> int:
            events2.append(data)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                with obj.program("trace_getpid").attach():
                    rb = tinybpf.BpfRingBuffer()
                    rb.add(obj.map("events"), callback1)
                    rb.add(obj.map("events2"), callback2)
                    with rb:
                        # Trigger events for both maps
                        subprocess.run(["/bin/true"], check=True)
                        os.getpid()
                        rb.poll(timeout_ms=100)

        assert len(events1) >= 1  # From execve
        assert len(events2) >= 1  # From getpid

    def test_ringbuf_add_wrong_map_type(self, test_maps_bpf_path: Path) -> None:
        """Adding non-RINGBUF map raises BpfError."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer()
            with pytest.raises(tinybpf.BpfError, match="expected RINGBUF"):
                rb.add(obj.map("pid_counts"), lambda d: 0)
            rb.close()

    def test_ringbuf_add_after_close(self, ringbuf_bpf_path: Path) -> None:
        """Adding after close raises BpfError."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer()
            rb.close()
            with pytest.raises(tinybpf.BpfError, match="closed"):
                rb.add(obj.map("events"), lambda d: 0)

    def test_ringbuf_add_duplicate_map(self, ringbuf_bpf_path: Path) -> None:
        """Adding same map twice raises BpfError."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
            with pytest.raises(tinybpf.BpfError, match="already added"):
                rb.add(obj.map("events"), lambda d: 0)
            rb.close()

    def test_ringbuf_multi_map_repr(self, ringbuf_bpf_path: Path) -> None:
        """Repr shows all map names for multi-map ring buffer."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer()
            rb.add(obj.map("events"), lambda d: 0)
            rb.add(obj.map("events2"), lambda d: 0)
            repr_str = repr(rb)
            assert "maps=" in repr_str
            assert "'events'" in repr_str
            assert "'events2'" in repr_str
            rb.close()

    def test_ringbuf_multi_map_callback_exception(self, ringbuf_bpf_path: Path) -> None:
        """Exception in any callback propagates."""
        events: list[bytes] = []

        def good_callback(data: bytes) -> int:
            events.append(data)
            return 0

        def bad_callback(data: bytes) -> int:
            raise ValueError("test error from callback2")

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_getpid").attach():
                rb = tinybpf.BpfRingBuffer()
                rb.add(obj.map("events"), good_callback)
                rb.add(obj.map("events2"), bad_callback)
                with rb:
                    os.getpid()  # Triggers events2
                    with pytest.raises(ValueError, match="test error from callback2"):
                        rb.poll(timeout_ms=100)

    def test_ringbuf_epoll_fd(self, ringbuf_bpf_path: Path) -> None:
        """epoll_fd() returns a valid file descriptor."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
            fd = rb.epoll_fd()
            assert isinstance(fd, int)
            assert fd >= 0
            # fileno() should return the same fd
            assert rb.fileno() == fd
            rb.close()

    def test_ringbuf_epoll_fd_without_maps(self) -> None:
        """epoll_fd() raises BpfError when no maps added."""
        rb = tinybpf.BpfRingBuffer()
        with pytest.raises(tinybpf.BpfError, match="No maps added"):
            rb.epoll_fd()
        rb.close()

    def test_ringbuf_mode_in_repr(self, ringbuf_bpf_path: Path) -> None:
        """Repr shows mode (callback or iterator)."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Callback mode
            rb_cb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
            assert "callback" in repr(rb_cb)
            rb_cb.close()

            # Iterator mode
            rb_it = tinybpf.BpfRingBuffer(obj.map("events"))
            assert "iterator" in repr(rb_it)
            rb_it.close()

    def test_ringbuf_mode_mixing_error(self, ringbuf_bpf_path: Path) -> None:
        """Cannot mix callback and iterator modes."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Start with callback mode, try to add iterator mode
            rb = tinybpf.BpfRingBuffer()
            rb.add(obj.map("events"), lambda d: 0)
            with pytest.raises(tinybpf.BpfError, match="Cannot mix callback and iterator"):
                rb.add(obj.map("events2"))  # No callback = iterator mode
            rb.close()

            # Start with iterator mode, try to add callback mode
            rb2 = tinybpf.BpfRingBuffer()
            rb2.add(obj.map("events"))  # No callback = iterator mode
            with pytest.raises(tinybpf.BpfError, match="Cannot mix callback and iterator"):
                rb2.add(obj.map("events2"), lambda d: 0)
            rb2.close()

    def test_ringbuf_iterate_on_callback_mode_error(self, ringbuf_bpf_path: Path) -> None:
        """Cannot iterate on callback-mode ring buffer."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
            with pytest.raises(tinybpf.BpfError, match="Cannot iterate on callback-mode"):
                iter(rb.__aiter__())  # Try to get async iterator
            rb.close()


class TestBpfRingBufferAsync:
    """Async tests for ring buffer operations."""

    @pytest.fixture
    def ringbuf_bpf_path(self) -> Path:
        """Path to compiled test_ringbuf.bpf.o test program."""
        path = BPF_DIR / "test_ringbuf.bpf.o"
        if not path.exists():
            pytest.skip(f"Compiled BPF program not found: {path}")
        return path

    async def test_ringbuf_poll_async_callback(self, ringbuf_bpf_path: Path) -> None:
        """poll_async() works with callback mode."""
        import subprocess

        events: list[bytes] = []

        def callback(data: bytes) -> int:
            events.append(data)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                async with tinybpf.BpfRingBuffer(obj.map("events"), callback) as rb:
                    # Trigger event
                    subprocess.run(["/bin/true"], check=True)
                    await rb.poll_async(timeout_ms=100)

        assert len(events) >= 1

    async def test_ringbuf_poll_async_timeout(self, ringbuf_bpf_path: Path) -> None:
        """poll_async() respects timeout."""
        import time

        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Don't attach program, so no events will come
            rb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
            start = time.monotonic()
            count = await rb.poll_async(timeout_ms=50)
            elapsed = time.monotonic() - start

            assert count == 0
            assert elapsed < 0.2  # Should timeout quickly, not wait forever
            rb.close()

    async def test_ringbuf_poll_async_nonblocking(self, ringbuf_bpf_path: Path) -> None:
        """poll_async(timeout_ms=0) is non-blocking."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0)
            count = await rb.poll_async(timeout_ms=0)
            assert count == 0
            rb.close()

    async def test_ringbuf_async_iterator(self, ringbuf_bpf_path: Path) -> None:
        """Async iteration yields events."""
        import asyncio
        import subprocess

        events: list[bytes] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                # Iterator mode: no callback
                rb = tinybpf.BpfRingBuffer(obj.map("events"))

                async def collect_events() -> None:
                    async for data in rb:
                        events.append(data)
                        if len(events) >= 1:
                            break

                async def trigger_events() -> None:
                    await asyncio.sleep(0.01)
                    subprocess.run(["/bin/true"], check=True)

                # Run both concurrently with timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(collect_events(), trigger_events()),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    pass
                finally:
                    rb.close()

        assert len(events) >= 1
        assert len(events[0]) == 24  # pid + tid + comm

    async def test_ringbuf_async_context_manager(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer supports async context manager."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            async with tinybpf.BpfRingBuffer(obj.map("events"), lambda d: 0) as rb:
                assert "open" in repr(rb)
            assert "closed" in repr(rb)


class TestBpfPerfBuffer:
    """Tests for perf buffer operations."""

    @pytest.fixture
    def perf_bpf_path(self) -> Path:
        """Path to compiled test_perf.bpf.o test program."""
        path = BPF_DIR / "test_perf.bpf.o"
        if not path.exists():
            pytest.skip(f"Compiled BPF program not found: {path}")
        return path

    def test_perfbuf_creation(self, perf_bpf_path: Path) -> None:
        """Can create perf buffer from perf event array map."""
        def callback(cpu: int, data: bytes) -> None:
            pass

        with tinybpf.load(perf_bpf_path) as obj:
            pb = tinybpf.BpfPerfBuffer(obj.map("events"), callback)
            assert "open" in repr(pb)
            pb.close()
            assert "closed" in repr(pb)

    def test_perfbuf_wrong_map_type(self, test_maps_bpf_path: Path) -> None:
        """Creating perf buffer from non-perf-event-array map raises BpfError."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            with pytest.raises(tinybpf.BpfError, match="PERF_EVENT_ARRAY"):
                tinybpf.BpfPerfBuffer(hash_map, lambda cpu, data: None)

    def test_perfbuf_invalid_page_count(self, perf_bpf_path: Path) -> None:
        """Invalid page_count raises ValueError."""
        with tinybpf.load(perf_bpf_path) as obj:
            with pytest.raises(ValueError, match="power of 2"):
                tinybpf.BpfPerfBuffer(obj.map("events"), lambda c, d: None, page_count=3)

    def test_perfbuf_poll_events(self, perf_bpf_path: Path) -> None:
        """Can poll and receive events with CPU info."""
        import os

        events: list[tuple[int, bytes]] = []

        def callback(cpu: int, data: bytes) -> None:
            events.append((cpu, data))

        with tinybpf.load(perf_bpf_path) as obj:
            prog = obj.program("trace_getpid")
            with prog.attach() as link:
                with tinybpf.BpfPerfBuffer(obj.map("events"), callback) as pb:
                    # Trigger getpid to generate event
                    os.getpid()
                    pb.poll(timeout_ms=100)

        assert len(events) >= 1
        cpu, data = events[0]
        assert isinstance(cpu, int)
        assert cpu >= 0
        # Verify event structure (pid, cpu, comm) = 4 + 4 + 16 = 24 bytes minimum
        # (actual size may include padding)
        assert len(data) >= 24
        # Verify we can extract the expected fields
        pid = int.from_bytes(data[0:4], "little")
        event_cpu = int.from_bytes(data[4:8], "little")
        assert pid > 0
        assert event_cpu >= 0

    def test_perfbuf_lost_callback(self, perf_bpf_path: Path) -> None:
        """Lost callback is invoked (basic wiring test)."""
        lost_events: list[tuple[int, int]] = []

        def sample_cb(cpu: int, data: bytes) -> None:
            pass

        def lost_cb(cpu: int, count: int) -> None:
            lost_events.append((cpu, count))

        with tinybpf.load(perf_bpf_path) as obj:
            # Just test that it can be created with lost callback
            with tinybpf.BpfPerfBuffer(obj.map("events"), sample_cb, lost_cb) as pb:
                assert pb is not None

    def test_perfbuf_callback_exception(self, perf_bpf_path: Path) -> None:
        """Exception in callback is propagated."""
        import os

        def bad_callback(cpu: int, data: bytes) -> None:
            raise ValueError("test error")

        with tinybpf.load(perf_bpf_path) as obj:
            prog = obj.program("trace_getpid")
            with prog.attach() as link:
                with tinybpf.BpfPerfBuffer(obj.map("events"), bad_callback) as pb:
                    os.getpid()
                    with pytest.raises(ValueError, match="test error"):
                        pb.poll(timeout_ms=100)

    def test_perfbuf_use_after_close(self, perf_bpf_path: Path) -> None:
        """Using perf buffer after close raises BpfError."""
        with tinybpf.load(perf_bpf_path) as obj:
            pb = tinybpf.BpfPerfBuffer(obj.map("events"), lambda c, d: None)
            pb.close()
            with pytest.raises(tinybpf.BpfError, match="closed"):
                pb.poll()

    def test_perfbuf_use_after_object_close(self, perf_bpf_path: Path) -> None:
        """Using perf buffer after BpfObject close raises BpfError."""
        obj = tinybpf.load(perf_bpf_path)
        pb = tinybpf.BpfPerfBuffer(obj.map("events"), lambda c, d: None)
        obj.close()
        with pytest.raises(tinybpf.BpfError, match="closed"):
            pb.poll()
        pb.close()

    def test_perfbuf_context_manager(self, perf_bpf_path: Path) -> None:
        """Perf buffer supports context manager protocol."""
        with tinybpf.load(perf_bpf_path) as obj:
            with tinybpf.BpfPerfBuffer(obj.map("events"), lambda c, d: None) as pb:
                assert "open" in repr(pb)
            # Perf buffer should be closed after with block
            assert "closed" in repr(pb)
