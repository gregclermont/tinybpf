"""Tests for BPF ring buffer async operations.

Run with: sudo pytest tests/test_ringbuf_async.py -v
"""

import asyncio
import os
import subprocess
import time
from pathlib import Path

import pytest

import tinybpf
from conftest import requires_root

pytestmark = requires_root


class TestBpfRingBufferAsync:
    """Async tests for ring buffer operations."""

    async def test_ringbuf_poll_async_callback(self, ringbuf_bpf_path: Path) -> None:
        """poll_async() works with callback mode."""
        events: list[bytes] = []

        def callback(data: bytes) -> int:
            events.append(data)
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                async with tinybpf.BpfRingBuffer(obj.maps["events"], callback) as rb:
                    # Trigger event
                    subprocess.run(["/bin/true"], check=True)
                    await rb.poll_async(timeout_ms=100)

        assert len(events) >= 1

    async def test_ringbuf_poll_async_timeout(self, ringbuf_bpf_path: Path) -> None:
        """poll_async() respects timeout."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Don't attach program, so no events will come
            rb = tinybpf.BpfRingBuffer(obj.maps["events"], lambda d: 0)
            start = time.monotonic()
            count = await rb.poll_async(timeout_ms=50)
            elapsed = time.monotonic() - start

            assert count == 0
            assert elapsed < 0.2  # Should timeout quickly, not wait forever
            rb.close()

    async def test_ringbuf_poll_async_nonblocking(self, ringbuf_bpf_path: Path) -> None:
        """poll_async(timeout_ms=0) is non-blocking."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.maps["events"], lambda d: 0)
            count = await rb.poll_async(timeout_ms=0)
            assert count == 0
            rb.close()

    async def test_ringbuf_async_iterator(self, ringbuf_bpf_path: Path) -> None:
        """Async iteration yields events."""
        events: list[bytes] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                # Iterator mode: no callback
                rb = tinybpf.BpfRingBuffer(obj.maps["events"])

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
                    pass  # Timeout is acceptable - we check events below
                finally:
                    rb.close()

        assert len(events) >= 1, "No events captured - async iteration may have timed out"
        assert len(events[0]) == 24  # pid + tid + comm

    async def test_ringbuf_async_context_manager(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer supports async context manager."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            async with tinybpf.BpfRingBuffer(obj.maps["events"], lambda d: 0) as rb:
                assert "open" in repr(rb)
            assert "closed" in repr(rb)

    async def test_ringbuf_tagged_events_single_map(self, ringbuf_bpf_path: Path) -> None:
        """Tagged events include map name for single map."""
        events: list[tinybpf.RingBufferEvent] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.maps["events"])

                async def collect() -> None:
                    async for event in rb.events():
                        events.append(event)
                        if len(events) >= 1:
                            break

                async def trigger() -> None:
                    await asyncio.sleep(0.01)
                    subprocess.run(["/bin/true"], check=True)

                try:
                    await asyncio.wait_for(
                        asyncio.gather(collect(), trigger()),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    pass  # Timeout is acceptable - we check events below
                finally:
                    rb.close()

        assert len(events) >= 1, "No events captured - async iteration may have timed out"
        assert events[0].map_name == "events"
        assert isinstance(events[0].data, bytes)
        assert len(events[0].data) == 24  # pid + tid + comm

    async def test_ringbuf_tagged_events_multi_map(self, ringbuf_bpf_path: Path) -> None:
        """Tagged events include correct map names for multi-map."""
        events: list[tinybpf.RingBufferEvent] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                with obj.program("trace_getpid").attach():
                    rb = tinybpf.BpfRingBuffer()
                    rb.add(obj.maps["events"])
                    rb.add(obj.maps["events2"])

                    async def collect() -> None:
                        async for event in rb.events():
                            events.append(event)
                            if len(events) >= 2:
                                break

                    async def trigger() -> None:
                        await asyncio.sleep(0.01)
                        subprocess.run(["/bin/true"], check=True)
                        os.getpid()

                    try:
                        await asyncio.wait_for(
                            asyncio.gather(collect(), trigger()),
                            timeout=2.0,
                        )
                    except asyncio.TimeoutError:
                        pass  # Timeout is acceptable - we check events below
                    finally:
                        rb.close()

        # Verify we got events and they have valid map names
        assert len(events) >= 1, "No events captured - async iteration may have timed out"
        map_names = {e.map_name for e in events}
        assert map_names <= {"events", "events2"}
        for event in events:
            assert isinstance(event, tinybpf.RingBufferEvent)
            assert isinstance(event.data, bytes)

    def test_ringbuf_tagged_events_on_callback_mode_error(self, ringbuf_bpf_path: Path) -> None:
        """events() raises error on callback-mode ring buffer."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer(obj.maps["events"], lambda d: 0)
            with pytest.raises(tinybpf.BpfError, match="callback-mode"):
                rb.events()
            rb.close()

    def test_ringbuf_event_dataclass(self) -> None:
        """RingBufferEvent dataclass has expected attributes."""
        event = tinybpf.RingBufferEvent(map_name="test_map", data=b"test_data")
        assert event.map_name == "test_map"
        assert event.data == b"test_data"
        # Frozen dataclass - should be hashable
        assert hash(event) is not None


class TestBpfRingBufferAsyncTyped:
    """Tests for typed events in async ring buffer operations."""

    async def test_ringbuf_poll_async_typed_callback(self, ringbuf_bpf_path: Path) -> None:
        """poll_async() works with typed callback."""
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
                async with tinybpf.BpfRingBuffer(
                    obj.maps["events"], callback, event_type=Event
                ) as rb:
                    subprocess.run(["/bin/true"], check=True)
                    await rb.poll_async(timeout_ms=100)

        assert len(events) >= 1, "No events captured"
        assert isinstance(events[0], Event)
        assert events[0].pid > 0

    async def test_ringbuf_async_iterator_typed(self, ringbuf_bpf_path: Path) -> None:
        """Async iteration yields typed events."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        events: list[Event] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.maps["events"], event_type=Event)

                async def collect() -> None:
                    async for event in rb:
                        events.append(event)
                        if len(events) >= 1:
                            break

                async def trigger() -> None:
                    await asyncio.sleep(0.01)
                    subprocess.run(["/bin/true"], check=True)

                try:
                    await asyncio.wait_for(
                        asyncio.gather(collect(), trigger()),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    pass
                finally:
                    rb.close()

        assert len(events) >= 1, "No events captured - async iteration may have timed out"
        assert isinstance(events[0], Event)
        assert events[0].pid > 0
        assert events[0].tid > 0

    async def test_ringbuf_tagged_events_typed(self, ringbuf_bpf_path: Path) -> None:
        """Tagged events with event_type return typed data."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        events: list[tinybpf.RingBufferEvent] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer(obj.maps["events"], event_type=Event)

                async def collect() -> None:
                    async for event in rb.events():
                        events.append(event)
                        if len(events) >= 1:
                            break

                async def trigger() -> None:
                    await asyncio.sleep(0.01)
                    subprocess.run(["/bin/true"], check=True)

                try:
                    await asyncio.wait_for(
                        asyncio.gather(collect(), trigger()),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    pass
                finally:
                    rb.close()

        assert len(events) >= 1, "No events captured - async iteration may have timed out"
        assert events[0].map_name == "events"
        # Data should be typed Event, not bytes
        assert isinstance(events[0].data, Event), f"Expected Event, got {type(events[0].data)}"
        assert events[0].data.pid > 0

    async def test_ringbuf_add_with_event_type(self, ringbuf_bpf_path: Path) -> None:
        """add() accepts event_type parameter."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        events: list[Event] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                rb = tinybpf.BpfRingBuffer()
                rb.add(obj.maps["events"], event_type=Event)

                async def collect() -> None:
                    async for event in rb:
                        events.append(event)
                        if len(events) >= 1:
                            break

                async def trigger() -> None:
                    await asyncio.sleep(0.01)
                    subprocess.run(["/bin/true"], check=True)

                try:
                    await asyncio.wait_for(
                        asyncio.gather(collect(), trigger()),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    pass
                finally:
                    rb.close()

        assert len(events) >= 1, "No events captured"
        assert isinstance(events[0], Event)

    async def test_ringbuf_add_validate_btf_struct_raises_when_not_found(
        self, ringbuf_bpf_path: Path
    ) -> None:
        """add() raises error when validate_btf_struct specifies non-existent struct."""
        import ctypes

        import pytest

        class MyEvent(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        def callback(event: MyEvent) -> int:
            return 0

        with tinybpf.load(ringbuf_bpf_path) as obj:
            rb = tinybpf.BpfRingBuffer()
            # validate_btf_struct is strict - error if struct not in BTF
            with pytest.raises(tinybpf.BpfError, match="not found"):
                rb.add(
                    obj.maps["events"],
                    callback,
                    event_type=MyEvent,
                    validate_btf_struct="nonexistent_struct",
                )
            rb.close()

    async def test_ringbuf_multi_map_tagged_typed(self, ringbuf_bpf_path: Path) -> None:
        """Multi-map tagged events with same event_type."""
        import ctypes

        class Event(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        events: list[tinybpf.RingBufferEvent] = []

        with tinybpf.load(ringbuf_bpf_path) as obj:
            with obj.program("trace_execve").attach():
                with obj.program("trace_getpid").attach():
                    rb = tinybpf.BpfRingBuffer()
                    rb.add(obj.maps["events"], event_type=Event)
                    rb.add(obj.maps["events2"], event_type=Event)

                    async def collect() -> None:
                        async for event in rb.events():
                            events.append(event)
                            if len(events) >= 2:
                                break

                    async def trigger() -> None:
                        await asyncio.sleep(0.01)
                        subprocess.run(["/bin/true"], check=True)
                        os.getpid()

                    try:
                        await asyncio.wait_for(
                            asyncio.gather(collect(), trigger()),
                            timeout=2.0,
                        )
                    except asyncio.TimeoutError:
                        pass
                    finally:
                        rb.close()

        assert len(events) >= 1, "No events captured"
        # All events should have typed data
        for event in events:
            assert isinstance(event.data, Event), f"Expected Event, got {type(event.data)}"
            assert event.map_name in {"events", "events2"}
