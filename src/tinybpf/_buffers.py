"""BPF event buffer consumers.

This module provides ring buffer and perf buffer consumers for receiving
events from BPF programs. Ring buffers (kernel 5.8+) are the modern
approach, while perf buffers (kernel 4.4+) provide legacy compatibility.
"""

from __future__ import annotations

import asyncio
import ctypes
import errno
from collections import deque
from typing import TYPE_CHECKING, Any, Generic, TypeVar, overload

from tinybpf._libbpf import bindings
from tinybpf._types import (
    BpfError,
    BpfMapType,
    BtfKind,
    RingBufferEvent,
    _check_err,
    _check_ptr,
    _from_event_bytes,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import TracebackType

    from tinybpf._map import BpfMap
    from tinybpf._object import BpfObject

T = TypeVar("T")


class BpfRingBuffer(Generic[T]):
    """Ring buffer consumer for BPF programs.

    Ring buffers (BPF_MAP_TYPE_RINGBUF, kernel 5.8+) are the modern
    replacement for perf buffers, offering better performance and simpler
    usage with a single shared buffer across all CPUs.

    Supports two consumption modes:

    **Callback mode**: Pass callbacks to handle events during poll().
        rb = BpfRingBuffer(obj.map("events"), handle_event)
        rb.poll()  # Callbacks invoked

    **Iterator mode**: Use async iteration to consume events.
        rb = BpfRingBuffer(obj.map("events"))
        async for data in rb:
            handle(data)

    Supports multiple maps in both modes:
        rb = BpfRingBuffer()
        rb.add(map1, callback1)  # Callback mode
        rb.add(map2, callback2)
        rb.poll()

        rb = BpfRingBuffer()
        rb.add(map1)  # Iterator mode
        rb.add(map2)
        async for data in rb:  # Events from all maps
            ...

    Modes cannot be mixed - all maps must use callbacks or none.

    **Typed events**: Use event_type to auto-convert events to ctypes.Structure:
        class Event(ctypes.Structure):
            _fields_ = [("pid", c_uint32), ("comm", c_char * 16)]

        rb = BpfRingBuffer(obj.map("events"), handle, event_type=Event)
        # callback receives Event instances instead of bytes

    In iterator mode, all maps must use the same event_type. For different
    event types per map, use callback mode instead.
    """

    @overload
    def __init__(
        self,
        map: BpfMap[Any, Any] | None = None,
        callback: Callable[[bytes], int] | Callable[[memoryview], int] | None = None,
        as_memoryview: bool = False,
        *,
        validate_btf_struct: str | None = None,
        validate_field_names: bool = True,
    ) -> None: ...

    @overload
    def __init__(
        self,
        map: BpfMap[Any, Any] | None = None,
        callback: Callable[[T], int] | None = None,
        as_memoryview: bool = False,
        *,
        event_type: type[T],
        validate_btf_struct: str | None = None,
        validate_field_names: bool = True,
    ) -> None: ...

    def __init__(
        self,
        map: BpfMap[Any, Any] | None = None,
        callback: Callable[[Any], int] | None = None,
        as_memoryview: bool = False,
        *,
        event_type: type[Any] = bytes,
        validate_btf_struct: str | None = None,
        validate_field_names: bool = True,
    ) -> None:
        """Create ring buffer consumer.

        Args:
            map: Optional ring buffer map to add initially.
            callback: Event handler for map's events. Return 0 to continue
                     polling, non-zero to stop. If None, use iteration to
                     consume events.

                     Callbacks are invoked synchronously during poll();
                     long-running callbacks can cause the kernel buffer to fill
                     and silently drop events. For heavy processing, use iterator
                     mode instead (omit callback) to automatically queue events
                     for processing after poll returns.
            as_memoryview: If True, callback receives memoryview instead of bytes,
                     providing zero-copy access to the ring buffer memory.

                     Useful when filtering events and discarding most without
                     allocating Python objects. You can inspect and slice the
                     memoryview without copying, then call bytes() only on the
                     portions you need to keep.

                     The benefit increases with event size and discard rate.
                     For most use cases, the default (bytes) is faster due to
                     Python object overhead. Profile your specific workload
                     to verify.

                     WARNING: The memoryview is only valid during callback
                     execution. To keep data beyond the callback, copy it:
                     kept = bytes(data)
            event_type: Type for automatic event conversion. Pass a
                     ctypes.Structure subclass to have events auto-converted.
                     Defaults to bytes (no conversion). Cannot be combined
                     with as_memoryview=True.
            validate_btf_struct: BTF struct name to validate event_type against.
                     If provided, validates at creation time that the Python
                     type matches the BTF struct's size and field layout. If
                     event_type is registered in the type registry, validation
                     happens automatically using the registered BTF name. If
                     neither, no BTF validation occurs (only runtime size
                     checking).

                     Note: Event structs used only locally in BPF functions
                     are often optimized out of BTF by the compiler. If you
                     get a "not found in BTF" error, add a global anchor in
                     your BPF code to preserve the struct:

                         struct event _event_btf __attribute__((unused));
            validate_field_names: Whether to validate that Python field names
                     match BTF field names when BTF validation occurs.
                     Defaults to True. Set to False to allow field renaming.

        Raises:
            ValueError: If callback is provided without map.
            BpfError: If as_memoryview=True without callback or with event_type,
                     or if validate_btf_struct conflicts with type registry.
            BtfValidationError: If event_type doesn't match BTF metadata.
        """
        # Set _closed early so __del__ works if __init__ raises
        self._closed = True

        # Validate: can't have callback without map
        if callback is not None and map is None:
            raise ValueError("callback requires map")

        # Validate: as_memoryview requires callback
        if as_memoryview and callback is None:
            raise BpfError("as_memoryview=True requires a callback")

        # Validate: as_memoryview and event_type are mutually exclusive
        if as_memoryview and event_type is not bytes:
            raise BpfError("Cannot use as_memoryview=True with event_type")

        self._ptr: Any = None  # Lazy init on first add()
        self._maps: list[BpfMap[Any, Any]] = []
        self._objs: set[BpfObject] = set()  # All parent objects for use-after-close
        self._callbacks: list[Any] = []  # Keep ctypes callbacks alive
        self._stored_exception: BaseException | None = None

        # Mode tracking: None until first add, then "callback" or "iterator"
        self._mode: str | None = None

        # Memoryview mode tracking
        self._as_memoryview = as_memoryview
        self._memoryview_mode: bool | None = None  # Track consistency across add() calls

        # Event type tracking for typed events
        self._event_type: type[Any] = event_type
        self._validate_btf_struct: str | None = validate_btf_struct
        self._validate_field_names: bool = validate_field_names
        # Per-map event types for callback mode (callback per map can have different types)
        self._per_map_event_types: dict[str, type[Any]] = {}

        # Event queue for iterator mode: (map_name, data) tuples
        self._event_queue: deque[tuple[str, bytes]] = deque()

        self._closed = False

        if map is not None:
            self.add(
                map,
                callback,
                as_memoryview=as_memoryview,
                event_type=event_type,
                validate_btf_struct=validate_btf_struct,
                validate_field_names=validate_field_names,
            )

    def _validate_event_type(
        self,
        map: BpfMap[Any, Any],
        event_type: type,
        validate_btf_struct: str | None,
        validate_field_names: bool,
    ) -> None:
        """Validate event_type against BTF metadata.

        Validation precedence:
        1. Explicit validate_btf_struct → use it (error if conflicts with registry)
        2. event_type in type registry → automatic validation via reverse lookup
        3. Neither → no BTF validation (only runtime size checking)

        Args:
            map: The ring buffer map (used to get BTF from parent object).
            event_type: The Python type to validate.
            validate_btf_struct: Explicit BTF struct name to validate against.
            validate_field_names: Whether to validate field names.

        Raises:
            BpfError: If validate_btf_struct conflicts with type registry.
            BtfValidationError: If validation finds a mismatch.
        """
        obj = map._obj
        if obj is None:
            return

        # Determine BTF struct name using precedence rules
        btf_struct_name: str | None = None

        # Check if type is registered in the registry
        registered_name = obj.lookup_btf_name(event_type)

        if validate_btf_struct is not None:
            # Explicit validate_btf_struct provided
            if registered_name is not None and registered_name != validate_btf_struct:
                # Conflict: type is registered with different name
                raise BpfError(
                    f"Type '{event_type.__name__}' is registered as BTF struct "
                    f"'{registered_name}', but validate_btf_struct='{validate_btf_struct}' "
                    f"was specified. Remove validate_btf_struct to use the registered "
                    f"mapping, or use a different Python type."
                )
            btf_struct_name = validate_btf_struct
        elif registered_name is not None:
            # Type is registered - use registered name for automatic validation
            btf_struct_name = registered_name
        else:
            # Not registered and no explicit name - no BTF validation
            return

        # Get BTF from map's parent object
        btf = obj.btf
        if btf is None:
            # No BTF available - can't validate
            if validate_btf_struct is not None:
                # User explicitly requested validation but BTF not available
                raise BpfError(
                    f"Cannot validate against BTF struct '{btf_struct_name}': "
                    "no BTF information available"
                )
            return

        lib = bindings._get_lib()

        # Find the BTF struct by name
        type_id = lib.btf__find_by_name_kind(btf, btf_struct_name.encode(), BtfKind.STRUCT)

        if type_id < 0:
            if validate_btf_struct is not None:
                # User explicitly requested validation but struct not found
                raise BpfError(
                    f"BTF struct '{btf_struct_name}' not found in BTF. "
                    f"Event structs used only locally in BPF functions are often optimized out. "
                    f"To include the struct in BTF, add a global anchor in your BPF code: "
                    f"struct {btf_struct_name} _{btf_struct_name}_btf __attribute__((unused));"
                )
            # Registered type but struct not in BTF - skip validation
            # (This shouldn't happen if register_type is strict, but handle it)
            return

        # Resolve and validate
        btf_type = obj._resolve_btf_type(type_id)
        if btf_type is not None:
            obj._validate_python_type(
                event_type, btf_type, validate_field_names=validate_field_names
            )

    @overload
    def add(
        self,
        map: BpfMap[Any, Any],
        callback: Callable[[bytes], int] | Callable[[memoryview], int] | None = None,
        as_memoryview: bool | None = None,
        *,
        validate_btf_struct: str | None = None,
        validate_field_names: bool | None = None,
    ) -> None: ...

    @overload
    def add(
        self,
        map: BpfMap[Any, Any],
        callback: Callable[[T], int] | None = None,
        as_memoryview: bool | None = None,
        *,
        event_type: type[T],
        validate_btf_struct: str | None = None,
        validate_field_names: bool | None = None,
    ) -> None: ...

    def add(  # noqa: PLR0912
        self,
        map: BpfMap[Any, Any],
        callback: Callable[[Any], int] | None = None,
        as_memoryview: bool | None = None,
        *,
        event_type: type[Any] | None = None,
        validate_btf_struct: str | None = None,
        validate_field_names: bool | None = None,
    ) -> None:
        """Add a ring buffer map to this consumer.

        Args:
            map: Ring buffer map (must be BPF_MAP_TYPE_RINGBUF).
            callback: Event handler. Return 0 to continue polling, non-zero
                     to stop. If None, events are consumed via iteration.
                     See __init__ docstring for timing considerations.
            as_memoryview: If True, callback receives memoryview instead of bytes.
                     If None, uses the instance default from constructor.
                     See __init__ docstring for full details on when this helps.
            event_type: Type for automatic event conversion. Pass a
                     ctypes.Structure subclass to have events auto-converted.
                     If None, uses the instance default from constructor.
                     In iterator mode, all maps must use the same event_type.
            validate_btf_struct: BTF struct name to validate against.
                     If None, uses instance default. If event_type is registered
                     in the type registry, validation happens automatically.
            validate_field_names: Whether to validate field names.
                     If None, uses the instance default from constructor.

        Raises:
            BpfError: If ring buffer is closed, map type is wrong,
                     map already added, modes are mixed, or libbpf call fails.
            BtfValidationError: If event_type doesn't match BTF metadata.
        """
        self._check_open()

        if map.type != BpfMapType.RINGBUF:
            raise BpfError(f"Map '{map.name}' is type {map.type.name}, expected RINGBUF")

        if map in self._maps:
            raise BpfError(f"Map '{map.name}' already added to this ring buffer")

        # Determine event_type (use instance default if not specified)
        use_event_type = event_type if event_type is not None else self._event_type

        # Determine memoryview mode (use instance default if not specified)
        use_memoryview = as_memoryview if as_memoryview is not None else self._as_memoryview

        # Memoryview mode requires callback
        if use_memoryview and callback is None:
            raise BpfError("as_memoryview=True requires a callback")

        # as_memoryview and event_type are mutually exclusive
        if use_memoryview and use_event_type is not bytes:
            raise BpfError("Cannot use as_memoryview=True with event_type")

        # Validate memoryview mode consistency
        if self._memoryview_mode is not None and self._memoryview_mode != use_memoryview:
            raise BpfError(
                f"Cannot mix memoryview and bytes modes; "
                f"ring buffer is in {'memoryview' if self._memoryview_mode else 'bytes'} mode"
            )
        self._memoryview_mode = use_memoryview

        # Determine and validate callback/iterator mode
        new_mode = "callback" if callback is not None else "iterator"
        if self._mode is not None and self._mode != new_mode:
            raise BpfError(
                f"Cannot mix callback and iterator modes; ring buffer is in {self._mode} mode"
            )
        self._mode = new_mode

        # In iterator mode, all maps must use the same event_type
        if new_mode == "iterator":
            # Check consistency: if we have maps already, event_type must match
            if self._maps and self._event_type != use_event_type:
                raise BpfError(
                    f"Cannot mix event types in iterator mode; "
                    f"ring buffer uses {self._event_type.__name__}, got {use_event_type.__name__}. "
                    f"Use callback mode for different event types per map."
                )
            # Update instance event_type for iterator mode
            self._event_type = use_event_type
        else:
            # Callback mode: track per-map event types
            self._per_map_event_types[map.name] = use_event_type

        # Validate event_type against BTF if applicable
        # Use parameters or fall back to instance defaults
        use_btf_struct = (
            validate_btf_struct if validate_btf_struct is not None else self._validate_btf_struct
        )
        use_field_names = (
            validate_field_names if validate_field_names is not None else self._validate_field_names
        )
        if use_event_type is not bytes:
            self._validate_event_type(map, use_event_type, use_btf_struct, use_field_names)

        # Create ctypes callback wrapper
        if callback is not None:
            if use_memoryview:
                # Memoryview mode: pass memoryview to callback (zero-copy)
                def _callback_wrapper(ctx: Any, data: Any, size: int) -> int:
                    try:
                        # Create memoryview without copying data
                        # Use c_char to get valid memoryview, then cast to 'B' for
                        # bytes-like interface (indexing returns int, not bytes)
                        array_type = ctypes.c_char * size
                        array_ptr = ctypes.cast(data, ctypes.POINTER(array_type))
                        mv = memoryview(array_ptr.contents).cast("B")
                        return callback(mv)
                    except BaseException as e:
                        self._stored_exception = e
                        return -1  # Stop polling
            else:
                # Bytes/typed mode: copy data and optionally convert
                map_event_type = use_event_type  # Capture in closure

                def _callback_wrapper(ctx: Any, data: Any, size: int) -> int:
                    try:
                        event_data = ctypes.string_at(data, size)
                        typed_event = _from_event_bytes(event_data, map_event_type)
                        return callback(typed_event)
                    except BaseException as e:
                        self._stored_exception = e
                        return -1  # Stop polling
        else:
            # Iterator mode: queue events with map name (conversion happens at iteration)
            map_name = map.name  # Capture in closure

            def _callback_wrapper(ctx: Any, data: Any, size: int) -> int:
                try:
                    event_data = ctypes.string_at(data, size)
                    self._event_queue.append((map_name, event_data))
                    return 0  # Continue
                except BaseException as e:
                    self._stored_exception = e
                    return -1

        cb = bindings.RING_BUFFER_SAMPLE_FN(_callback_wrapper)
        lib = bindings._get_lib()

        if self._ptr is None:
            # First map: create ring buffer
            self._ptr = lib.ring_buffer__new(map.fd, cb, None, None)
            _check_ptr(self._ptr, "ring_buffer__new")
        else:
            # Additional maps: add to existing ring buffer
            ret = lib.ring_buffer__add(self._ptr, map.fd, cb, None)
            _check_err(ret, "ring_buffer__add")

        # Track for lifecycle management
        self._maps.append(map)
        if map._obj is not None:
            self._objs.add(map._obj)
        self._callbacks.append(cb)

    def _check_open(self) -> None:
        """Raise if ring buffer is closed or any parent BpfObject is closed."""
        if self._closed:
            raise BpfError("Ring buffer is closed")
        for obj in self._objs:
            if obj._closed:
                raise BpfError("Cannot use ring buffer after BpfObject is closed")

    def _check_and_reraise(self) -> None:
        """Re-raise any exception stored from callback."""
        if self._stored_exception is not None:
            exc = self._stored_exception
            self._stored_exception = None
            raise exc

    def epoll_fd(self) -> int:
        """Return the epoll file descriptor for this ring buffer.

        This fd becomes readable when events are available. Can be used
        for custom event loop integration.

        Returns:
            File descriptor for epoll-based waiting.

        Raises:
            BpfError: If no maps have been added.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")
        lib = bindings._get_lib()
        return lib.ring_buffer__epoll_fd(self._ptr)

    def fileno(self) -> int:
        """Return file descriptor for select/poll integration.

        Alias for epoll_fd(), provided for compatibility with Python's
        file-like object protocol.
        """
        return self.epoll_fd()

    def poll(self, timeout_ms: int = -1, ignore_eintr: bool = True) -> int:
        """Poll for events (blocking).

        Waits for events and processes them. In callback mode, callbacks
        are invoked. In iterator mode, events are queued for async iteration.

        Args:
            timeout_ms: Timeout in milliseconds. -1 for infinite wait,
                       0 for non-blocking.
            ignore_eintr: If True (default), return 0 when interrupted by a
                       signal (EINTR) instead of raising BpfError. This is the
                       common case for graceful shutdown with signal handlers.
                       Set to False to raise BpfError on EINTR.

        Returns:
            Number of events consumed, or 0 if interrupted by signal and
            ignore_eintr is True.

        Raises:
            BpfError: On system error or if no maps have been added.
            Any exception raised by callbacks.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")
        lib = bindings._get_lib()
        ret = lib.ring_buffer__poll(self._ptr, timeout_ms)
        self._check_and_reraise()
        if ret < 0 and abs(ret) == errno.EINTR and ignore_eintr:
            return 0
        _check_err(ret, "ring_buffer__poll")
        return ret

    def consume(self) -> int:
        """Consume all available events without waiting.

        Processes all events currently in the ring buffer without blocking.

        Returns:
            Number of events consumed.

        Raises:
            BpfError: On system error or if no maps have been added.
            Any exception raised by callbacks.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")
        lib = bindings._get_lib()
        ret = lib.ring_buffer__consume(self._ptr)
        self._check_and_reraise()
        _check_err(ret, "ring_buffer__consume")
        return ret

    async def poll_async(self, timeout_ms: int = -1) -> int:
        """Poll for events asynchronously.

        Waits for events using asyncio event loop integration. In callback
        mode, callbacks are invoked when events arrive. In iterator mode,
        events are queued for async iteration.

        Args:
            timeout_ms: Timeout in milliseconds. -1 for infinite wait,
                       0 for non-blocking.

        Returns:
            Number of events consumed.

        Raises:
            BpfError: On system error or if no maps have been added.
            Any exception raised by callbacks.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")

        if timeout_ms == 0:
            # Non-blocking: just consume
            return self.consume()

        loop = asyncio.get_running_loop()
        fd = self.epoll_fd()

        # Create future to wait on fd readability
        future: asyncio.Future[None] = loop.create_future()

        def on_readable() -> None:
            if not future.done():
                loop.remove_reader(fd)
                future.set_result(None)

        loop.add_reader(fd, on_readable)

        try:
            if timeout_ms > 0:
                try:
                    await asyncio.wait_for(future, timeout=timeout_ms / 1000)
                except asyncio.TimeoutError:
                    return 0
            else:
                await future

            # Events available, consume them
            return self.consume()
        finally:
            # Ensure reader is removed even on cancellation
            try:
                loop.remove_reader(fd)
            except (ValueError, KeyError):
                pass  # Already removed

    def __aiter__(self) -> _AsyncRingBufferIterator[T]:
        """Return async iterator over events.

        Only available in iterator mode (maps added without callbacks).

        Returns:
            Async iterator yielding event data (type depends on event_type).

        Raises:
            BpfError: If ring buffer is in callback mode or no maps added.
        """
        if self._mode == "callback":
            raise BpfError(
                "Cannot iterate on callback-mode ring buffer; "
                "events are delivered to callbacks during poll()"
            )
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")
        return _AsyncRingBufferIterator(self)

    def __iter__(self) -> Iterator[T]:
        """Iterate over queued events synchronously.

        Only available in iterator mode (maps added without callbacks).
        Events must be received first by calling poll().

        Example:
            rb = BpfRingBuffer(obj.map("events"))
            rb.poll(timeout_ms=1000)
            for event in rb:
                process(event)

        Yields:
            Event data (type depends on event_type parameter).

        Raises:
            BpfError: If ring buffer is in callback mode.
        """
        if self._mode == "callback":
            raise BpfError(
                "Cannot iterate on callback-mode ring buffer; "
                "events are delivered to callbacks during poll()"
            )
        while self._event_queue:
            _map_name, data = self._event_queue.popleft()
            yield _from_event_bytes(data, self._event_type)

    def events(self) -> _TaggedRingBufferIterator[T]:
        """Return async iterator yielding tagged events.

        Each event includes the source map name, useful for multi-map
        ring buffers where you need to identify which map each event
        came from.

        Returns:
            Async iterator yielding RingBufferEvent[T] objects.

        Raises:
            BpfError: If in callback mode or no maps added.

        Example:
            rb = BpfRingBuffer()
            rb.add(obj.map("events1"))
            rb.add(obj.map("events2"))
            async for event in rb.events():
                if event.map_name == "events1":
                    handle_type1(event.data)
                else:
                    handle_type2(event.data)
        """
        if self._mode == "callback":
            raise BpfError(
                "Cannot iterate on callback-mode ring buffer; "
                "events are delivered to callbacks during poll()"
            )
        if self._ptr is None:
            raise BpfError("No maps added to ring buffer")
        return _TaggedRingBufferIterator(self)

    def close(self) -> None:
        """Close ring buffer and free resources."""
        if not self._closed:
            if self._ptr is not None:
                lib = bindings._get_lib()
                lib.ring_buffer__free(self._ptr)
            self._closed = True

    def __enter__(self) -> BpfRingBuffer[T]:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    async def __aenter__(self) -> BpfRingBuffer[T]:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            self.close()

    def __repr__(self) -> str:
        status = "closed" if self._closed else "open"
        mode = f" {self._mode}" if self._mode else ""
        if len(self._maps) == 0:
            return f"<BpfRingBuffer (no maps){mode} {status}>"
        elif len(self._maps) == 1:
            return f"<BpfRingBuffer map='{self._maps[0].name}'{mode} {status}>"
        else:
            names = ", ".join(f"'{m.name}'" for m in self._maps)
            return f"<BpfRingBuffer maps=[{names}]{mode} {status}>"


class _AsyncRingBufferIterator(Generic[T]):
    """Async iterator for BpfRingBuffer events."""

    def __init__(self, rb: BpfRingBuffer[T]) -> None:
        self._rb = rb

    def __aiter__(self) -> _AsyncRingBufferIterator[T]:
        return self

    async def __anext__(self) -> T:
        """Get next event, waiting if necessary."""
        rb = self._rb

        # Check if ring buffer is still valid
        rb._check_open()

        # Return queued event if available (discard map_name for backward compat)
        if rb._event_queue:
            _map_name, data = rb._event_queue.popleft()
            return _from_event_bytes(data, rb._event_type)

        # Wait for events
        while True:
            await rb.poll_async(timeout_ms=-1)

            # Check for events after poll
            if rb._event_queue:
                _map_name, data = rb._event_queue.popleft()
                return _from_event_bytes(data, rb._event_type)

            # poll_async returned 0 events, could be spurious wakeup
            # Continue waiting


class _TaggedRingBufferIterator(Generic[T]):
    """Async iterator yielding tagged RingBufferEvent objects."""

    def __init__(self, rb: BpfRingBuffer[T]) -> None:
        self._rb = rb

    def __aiter__(self) -> _TaggedRingBufferIterator[T]:
        return self

    async def __anext__(self) -> RingBufferEvent[T]:
        """Get next tagged event, waiting if necessary."""
        rb = self._rb

        # Check if ring buffer is still valid
        rb._check_open()

        # Return queued event if available
        if rb._event_queue:
            map_name, data = rb._event_queue.popleft()
            typed_data = _from_event_bytes(data, rb._event_type)
            return RingBufferEvent(map_name=map_name, data=typed_data)

        # Wait for events
        while True:
            await rb.poll_async(timeout_ms=-1)

            # Check for events after poll
            if rb._event_queue:
                map_name, data = rb._event_queue.popleft()
                typed_data = _from_event_bytes(data, rb._event_type)
                return RingBufferEvent(map_name=map_name, data=typed_data)

            # poll_async returned 0 events, could be spurious wakeup
            # Continue waiting


class BpfPerfBuffer(Generic[T]):
    """Perf buffer consumer for BPF programs.

    Perf buffers (BPF_MAP_TYPE_PERF_EVENT_ARRAY) are available on kernel 4.4+
    and provide per-CPU event buffers with lost event tracking.

    Example:
        def handle_event(cpu: int, data: bytes) -> None:
            print(f"CPU {cpu}: {len(data)} bytes")

        def handle_lost(cpu: int, count: int) -> None:
            print(f"CPU {cpu}: lost {count} events")

        with tinybpf.load("trace.bpf.o") as obj:
            with obj.program("trace").attach():
                with BpfPerfBuffer(obj.map("events"), handle_event, handle_lost) as pb:
                    pb.poll(timeout_ms=1000)

    **Typed events**: Use event_type to auto-convert events to ctypes.Structure:
        class Event(ctypes.Structure):
            _fields_ = [("pid", c_uint32), ("comm", c_char * 16)]

        def handle(cpu: int, event: Event) -> None:
            print(cpu, event.pid)

        pb = BpfPerfBuffer(obj.map("events"), handle, event_type=Event)
    """

    @overload
    def __init__(
        self,
        map: BpfMap[Any, Any],
        sample_callback: Callable[[int, bytes], None],
        lost_callback: Callable[[int, int], None] | None = None,
        page_count: int = 8,
        *,
        validate_btf_struct: str | None = None,
        validate_field_names: bool = True,
    ) -> None: ...

    @overload
    def __init__(
        self,
        map: BpfMap[Any, Any],
        sample_callback: Callable[[int, T], None],
        lost_callback: Callable[[int, int], None] | None = None,
        page_count: int = 8,
        *,
        event_type: type[T],
        validate_btf_struct: str | None = None,
        validate_field_names: bool = True,
    ) -> None: ...

    def __init__(
        self,
        map: BpfMap[Any, Any],
        sample_callback: Callable[[int, Any], None],
        lost_callback: Callable[[int, int], None] | None = None,
        page_count: int = 8,
        *,
        event_type: type[Any] = bytes,
        validate_btf_struct: str | None = None,
        validate_field_names: bool = True,
    ) -> None:
        """Create perf buffer consumer.

        Args:
            map: Perf event array map (must be BPF_MAP_TYPE_PERF_EVENT_ARRAY).
            sample_callback: Called with (cpu, data) for each event.
                     Callbacks are invoked synchronously during poll();
                     long-running callbacks can cause events to be lost. For
                     heavy processing, append to a collections.deque and process
                     in a separate thread or after polling completes.
            lost_callback: Called with (cpu, lost_count) when events are dropped.
                          If None, lost events are silently ignored.
            page_count: Per-CPU buffer size in pages (must be power of 2).
            event_type: Type for automatic event conversion. Pass a
                     ctypes.Structure subclass to have events auto-converted.
                     Defaults to bytes (no conversion).
            validate_btf_struct: BTF struct name to validate event_type against.
                     If provided, validates at creation time. If event_type is
                     registered in the type registry, validation happens
                     automatically using the registered BTF name.
            validate_field_names: Whether to validate that Python field names
                     match BTF field names when BTF validation occurs.
                     Defaults to True. Set to False to allow field renaming.

        Raises:
            BpfError: If map is not a perf event array type, or if
                     validate_btf_struct conflicts with type registry.
            ValueError: If page_count is not a power of 2.
            BtfValidationError: If event_type doesn't match BTF metadata.
        """
        # Set _closed early so __del__ works if __init__ raises
        self._closed = True

        if map.type != BpfMapType.PERF_EVENT_ARRAY:
            raise BpfError(f"Map '{map.name}' is type {map.type.name}, expected PERF_EVENT_ARRAY")

        if page_count <= 0 or (page_count & (page_count - 1)) != 0:
            raise ValueError(f"page_count must be a power of 2, got {page_count}")

        # Validate event_type against BTF if applicable
        if event_type is not bytes:
            self._validate_event_type(map, event_type, validate_btf_struct, validate_field_names)

        self._map = map
        self._obj = map._obj  # For use-after-close detection
        self._user_sample_callback = sample_callback
        self._user_lost_callback = lost_callback
        self._event_type = event_type
        self._stored_exception: BaseException | None = None

        # Create ctypes callback wrappers
        def _sample_wrapper(ctx: Any, cpu: int, data: Any, size: int) -> None:
            try:
                event_data = ctypes.string_at(data, size)
                # Perf buffers may have up to 7 bytes of trailing padding/garbage
                # due to kernel alignment requirements, so use strict_size=False
                typed_event = _from_event_bytes(event_data, self._event_type, strict_size=False)
                self._user_sample_callback(cpu, typed_event)
            except BaseException as e:
                self._stored_exception = e

        def _lost_wrapper(ctx: Any, cpu: int, lost_cnt: int) -> None:
            if self._user_lost_callback is not None:
                try:
                    self._user_lost_callback(cpu, lost_cnt)
                except BaseException as e:
                    if self._stored_exception is None:
                        self._stored_exception = e

        # Keep references to prevent garbage collection
        self._sample_cb = bindings.PERF_BUFFER_SAMPLE_FN(_sample_wrapper)
        self._lost_cb = bindings.PERF_BUFFER_LOST_FN(_lost_wrapper)

        lib = bindings._get_lib()
        self._ptr = lib.perf_buffer__new(
            map.fd, page_count, self._sample_cb, self._lost_cb, None, None
        )
        _check_ptr(self._ptr, "perf_buffer__new")

        # Mark as open only after successful initialization
        self._closed = False

    def _check_open(self) -> None:
        """Raise if parent BpfObject is closed or perf buffer is closed."""
        if self._closed:
            raise BpfError("Perf buffer is closed")
        if self._obj is not None and self._obj._closed:
            raise BpfError("Cannot use perf buffer after BpfObject is closed")

    def _check_and_reraise(self) -> None:
        """Re-raise any exception stored from callback."""
        if self._stored_exception is not None:
            exc = self._stored_exception
            self._stored_exception = None
            raise exc

    def _validate_event_type(
        self,
        map: BpfMap[Any, Any],
        event_type: type,
        validate_btf_struct: str | None,
        validate_field_names: bool,
    ) -> None:
        """Validate event_type against BTF metadata.

        Validation precedence:
        1. Explicit validate_btf_struct → use it (error if conflicts with registry)
        2. event_type in type registry → automatic validation via reverse lookup
        3. Neither → no BTF validation (only runtime size checking)

        Args:
            map: The perf buffer map (used to get BTF from parent object).
            event_type: The Python type to validate.
            validate_btf_struct: Explicit BTF struct name to validate against.
            validate_field_names: Whether to validate field names.

        Raises:
            BpfError: If validate_btf_struct conflicts with type registry.
            BtfValidationError: If validation finds a mismatch.
        """
        obj = map._obj
        if obj is None:
            return

        # Determine BTF struct name using precedence rules
        btf_struct_name: str | None = None

        # Check if type is registered in the registry
        registered_name = obj.lookup_btf_name(event_type)

        if validate_btf_struct is not None:
            # Explicit validate_btf_struct provided
            if registered_name is not None and registered_name != validate_btf_struct:
                # Conflict: type is registered with different name
                raise BpfError(
                    f"Type '{event_type.__name__}' is registered as BTF struct "
                    f"'{registered_name}', but validate_btf_struct='{validate_btf_struct}' "
                    f"was specified. Remove validate_btf_struct to use the registered "
                    f"mapping, or use a different Python type."
                )
            btf_struct_name = validate_btf_struct
        elif registered_name is not None:
            # Type is registered - use registered name for automatic validation
            btf_struct_name = registered_name
        else:
            # Not registered and no explicit name - no BTF validation
            return

        # Get BTF from map's parent object
        btf = obj.btf
        if btf is None:
            # No BTF available - can't validate
            if validate_btf_struct is not None:
                # User explicitly requested validation but BTF not available
                raise BpfError(
                    f"Cannot validate against BTF struct '{btf_struct_name}': "
                    "no BTF information available"
                )
            return

        lib = bindings._get_lib()

        # Find the BTF struct by name
        type_id = lib.btf__find_by_name_kind(btf, btf_struct_name.encode(), BtfKind.STRUCT)

        if type_id < 0:
            if validate_btf_struct is not None:
                # User explicitly requested validation but struct not found
                raise BpfError(
                    f"BTF struct '{btf_struct_name}' not found in BTF. "
                    f"Event structs used only locally in BPF functions are often optimized out. "
                    f"To include the struct in BTF, add a global anchor in your BPF code: "
                    f"struct {btf_struct_name} _{btf_struct_name}_btf __attribute__((unused));"
                )
            # Registered type but struct not in BTF - skip validation
            return

        # Resolve and validate
        btf_type = obj._resolve_btf_type(type_id)
        if btf_type is not None:
            obj._validate_python_type(
                event_type, btf_type, validate_field_names=validate_field_names
            )

    def poll(self, timeout_ms: int = -1, ignore_eintr: bool = True) -> int:
        """Poll for events from all CPUs.

        Args:
            timeout_ms: Timeout in milliseconds. -1 for infinite wait,
                       0 for non-blocking.
            ignore_eintr: If True (default), return 0 when interrupted by a
                       signal (EINTR) instead of raising BpfError. This is the
                       common case for graceful shutdown with signal handlers.
                       Set to False to raise BpfError on EINTR.

        Returns:
            Number of events consumed, or 0 if interrupted by signal and
            ignore_eintr is True.

        Raises:
            BpfError: On system error.
            Any exception raised by the callbacks.
        """
        self._check_open()
        lib = bindings._get_lib()
        ret = lib.perf_buffer__poll(self._ptr, timeout_ms)
        self._check_and_reraise()
        if ret < 0 and abs(ret) == errno.EINTR and ignore_eintr:
            return 0
        _check_err(ret, "perf_buffer__poll")
        return ret

    def consume(self) -> int:
        """Consume all available events without waiting.

        Returns:
            Number of events consumed.

        Raises:
            BpfError: On system error.
            Any exception raised by the callbacks.
        """
        self._check_open()
        lib = bindings._get_lib()
        ret = lib.perf_buffer__consume(self._ptr)
        self._check_and_reraise()
        _check_err(ret, "perf_buffer__consume")
        return ret

    def close(self) -> None:
        """Close perf buffer and free resources."""
        if not self._closed:
            lib = bindings._get_lib()
            lib.perf_buffer__free(self._ptr)
            self._closed = True

    def __enter__(self) -> BpfPerfBuffer[T]:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            self.close()

    def __repr__(self) -> str:
        status = "closed" if self._closed else "open"
        return f"<BpfPerfBuffer map='{self._map.name}' {status}>"
