"""Tests for BPF ring buffer operations (synchronous).

Run with: sudo pytest tests/test_ringbuf.py -v
"""

import os
import subprocess
from pathlib import Path

import pytest

import tinybpf
from conftest import requires_root

pytestmark = requires_root


class TestBpfRingBuffer:
    """Tests for ring buffer operations."""

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
                rb.__aiter__()  # Try to get async iterator
            rb.close()

    def test_ringbuf_as_memoryview_callback(self, ringbuf_bpf_path: Path) -> None:
        """Memoryview mode provides memoryview to callback."""
        received_types: list[type] = []
        received_lengths: list[int] = []

        def callback(data: memoryview) -> int:
            received_types.append(type(data))
            received_lengths.append(len(data))
            # Can access data without copying
            assert isinstance(data, memoryview)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.map("events"), callback, as_memoryview=True)
                subprocess.run(["/bin/true"], check=True)
                rb.poll(timeout_ms=100)
                rb.close()

        assert len(received_types) >= 1
        assert all(t is memoryview for t in received_types)
        assert all(length == 24 for length in received_lengths)  # pid + tid + comm

    def test_ringbuf_as_memoryview_filter(self, ringbuf_bpf_path: Path) -> None:
        """Memoryview mode allows inspection without copying."""
        inspected_count = [0]
        copied_count = [0]

        def callback(data: memoryview) -> int:
            inspected_count[0] += 1
            # Inspect first byte without copying
            first_byte = data[0]
            # Only copy if we decide to keep (simulate filtering)
            if first_byte != 0:
                _ = bytes(data)  # Copy only when needed
                copied_count[0] += 1
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.map("events"), callback, as_memoryview=True)
                subprocess.run(["/bin/true"], check=True)
                rb.poll(timeout_ms=100)
                rb.close()

        assert inspected_count[0] >= 1

    def test_ringbuf_as_memoryview_requires_callback(self, ringbuf_bpf_path: Path) -> None:
        """as_memoryview=True requires callback mode."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            with pytest.raises(tinybpf.BpfError, match="requires a callback"):
                tinybpf.BpfRingBuffer(obj.map("events"), as_memoryview=True)

    def test_ringbuf_as_memoryview_add_requires_callback(self, ringbuf_bpf_path: Path) -> None:
        """as_memoryview=True on add() requires callback."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer()
            with pytest.raises(tinybpf.BpfError, match="requires a callback"):
                rb.add(obj.map("events"), as_memoryview=True)
            rb.close()

    def test_ringbuf_memoryview_mode_mixing_error(self, ringbuf_bpf_path: Path) -> None:
        """Cannot mix memoryview and bytes modes in same ring buffer."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer()
            rb.add(obj.map("events"), lambda d: 0, as_memoryview=True)
            with pytest.raises(tinybpf.BpfError, match="Cannot mix memoryview and bytes"):
                rb.add(obj.map("events2"), lambda d: 0, as_memoryview=False)
            rb.close()

    def test_ringbuf_sync_iteration(self, ringbuf_bpf_path: Path) -> None:
        """Can iterate over queued events synchronously."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.map("events"))
                subprocess.run(["/bin/true"], check=True)
                rb.poll(timeout_ms=100)

                events = list(rb)  # Sync iteration
                assert len(events) >= 1
                assert all(isinstance(e, bytes) for e in events)

                rb.close()

    def test_ringbuf_sync_iteration_drains_queue(self, ringbuf_bpf_path: Path) -> None:
        """Sync iteration drains the event queue."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.map("events"))
                subprocess.run(["/bin/true"], check=True)
                rb.poll(timeout_ms=100)

                # First iteration drains the queue
                events1 = list(rb)
                assert len(events1) >= 1

                # Second iteration should be empty (queue drained)
                events2 = list(rb)
                assert len(events2) == 0

                rb.close()

    def test_ringbuf_sync_iteration_callback_mode_error(self, ringbuf_bpf_path: Path) -> None:
        """Sync iteration on callback mode raises error."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.map("events"), callback=lambda d: 0)
            with pytest.raises(tinybpf.BpfError, match="callback-mode"):
                list(rb)
            rb.close()


class TestBpfRingBufferTyped:
    """Tests for typed ring buffer events."""

    def test_ringbuf_typed_callback(self, ringbuf_bpf_path: Path) -> None:
        """Typed callback receives ctypes.Structure events."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        events: list[Event] = []

        def callback(event: Event) -> int:
            events.append(event)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.map("events"), callback, event_type=Event)
                subprocess.run(["/bin/true"], check=True)
                rb.poll(timeout_ms=100)
                rb.close()

        assert len(events) >= 1
        event = events[0]
        assert isinstance(event, Event)
        assert event.pid > 0
        assert event.tid > 0
        # comm should contain process name
        assert len(event.comm) > 0

    def test_ringbuf_typed_iterator(self, ringbuf_bpf_path: Path) -> None:
        """Typed iterator yields ctypes.Structure events."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.map("events"), event_type=Event)
                subprocess.run(["/bin/true"], check=True)
                rb.poll(timeout_ms=100)

                events = list(rb)  # Sync iteration
                assert len(events) >= 1
                event = events[0]
                assert isinstance(event, Event)
                assert event.pid > 0

                rb.close()

    def test_ringbuf_default_bytes_backward_compat(self, ringbuf_bpf_path: Path) -> None:
        """Default (no event_type) returns bytes for backward compat."""
        events: list[bytes] = []

        def callback(data: bytes) -> int:
            events.append(data)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.map("events"), callback)
                subprocess.run(["/bin/true"], check=True)
                rb.poll(timeout_ms=100)
                rb.close()

        assert len(events) >= 1
        assert isinstance(events[0], bytes)
        assert len(events[0]) == 24  # pid + tid + comm

    def test_ringbuf_typed_memoryview_incompatible(self, ringbuf_bpf_path: Path) -> None:
        """as_memoryview=True is incompatible with event_type."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [("pid", ctypes.c_uint32)]

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with pytest.raises(tinybpf.BpfError, match="Cannot use as_memoryview"):
                tinybpf.BpfRingBuffer(
                    obj.map("events"),
                    lambda d: 0,
                    as_memoryview=True,
                    event_type=Event,
                )

    def test_ringbuf_multi_map_callback_different_types(self, ringbuf_bpf_path: Path) -> None:
        """Multi-map callback mode can have different event types per map."""
        import ctypes

        class Event1(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        class Event2(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        events1: list[Event1] = []
        events2: list[Event2] = []

        def callback1(event: Event1) -> int:
            events1.append(event)
            return 0

        def callback2(event: Event2) -> int:
            events2.append(event)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                with obj.program("trace_getpid").attach():
                    rb = tinybpf.BpfRingBuffer()
                    rb.add(obj.map("events"), callback1, event_type=Event1)
                    rb.add(obj.map("events2"), callback2, event_type=Event2)
                    with rb:
                        subprocess.run(["/bin/true"], check=True)
                        os.getpid()
                        rb.poll(timeout_ms=100)

        assert len(events1) >= 1
        assert len(events2) >= 1
        assert isinstance(events1[0], Event1)
        assert isinstance(events2[0], Event2)

    def test_ringbuf_multi_map_iterator_same_type(self, ringbuf_bpf_path: Path) -> None:
        """Multi-map iterator mode requires same event type for all maps."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                with obj.program("trace_getpid").attach():
                    rb = tinybpf.BpfRingBuffer()
                    rb.add(obj.map("events"), event_type=Event)
                    rb.add(obj.map("events2"), event_type=Event)

                    subprocess.run(["/bin/true"], check=True)
                    os.getpid()
                    rb.poll(timeout_ms=100)

                    events = list(rb)
                    assert len(events) >= 2
                    assert all(isinstance(e, Event) for e in events)
                    rb.close()

    def test_ringbuf_multi_map_iterator_type_mismatch_error(self, ringbuf_bpf_path: Path) -> None:
        """Multi-map iterator mode raises error on mismatched event types."""
        import ctypes

        class Event1(ctypes.Structure):
            _fields_ = [("pid", ctypes.c_uint32)]

        class Event2(ctypes.Structure):
            _fields_ = [("tid", ctypes.c_uint32)]

        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer()
            rb.add(obj.map("events"), event_type=Event1)
            with pytest.raises(tinybpf.BpfError, match="Cannot mix event types"):
                rb.add(obj.map("events2"), event_type=Event2)
            rb.close()
