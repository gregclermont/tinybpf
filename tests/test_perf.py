"""Tests for BPF perf buffer operations.

Run with: sudo pytest tests/test_perf.py -v
"""

import os
from pathlib import Path

import pytest

import tinybpf
from conftest import requires_root

pytestmark = requires_root


class TestBpfPerfBuffer:
    """Tests for perf buffer operations."""

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


class TestBpfPerfBufferTyped:
    """Tests for typed perf buffer events."""

    def test_perfbuf_typed_callback(self, perf_bpf_path: Path) -> None:
        """Typed callback receives ctypes.Structure events."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("cpu", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        events: list[tuple[int, Event]] = []

        def callback(cpu: int, event: Event) -> None:
            events.append((cpu, event))

        with tinybpf.load(perf_bpf_path) as obj:
            with obj.program("trace_getpid").attach():
                with tinybpf.BpfPerfBuffer(obj.map("events"), callback, event_type=Event) as pb:
                    os.getpid()
                    pb.poll(timeout_ms=100)

        assert len(events) >= 1
        cpu, event = events[0]
        assert isinstance(cpu, int)
        assert isinstance(event, Event)
        assert event.pid > 0
        assert event.cpu >= 0
        assert len(event.comm) > 0

    def test_perfbuf_default_bytes_backward_compat(self, perf_bpf_path: Path) -> None:
        """Default (no event_type) returns bytes for backward compat."""
        events: list[tuple[int, bytes]] = []

        def callback(cpu: int, data: bytes) -> None:
            events.append((cpu, data))

        with tinybpf.load(perf_bpf_path) as obj:
            with obj.program("trace_getpid").attach():
                with tinybpf.BpfPerfBuffer(obj.map("events"), callback) as pb:
                    os.getpid()
                    pb.poll(timeout_ms=100)

        assert len(events) >= 1
        cpu, data = events[0]
        assert isinstance(cpu, int)
        assert isinstance(data, bytes)
        assert len(data) >= 24  # pid + cpu + comm
