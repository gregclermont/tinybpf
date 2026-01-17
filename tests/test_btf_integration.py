"""Integration tests for BTF type inference features.

Run with: sudo pytest tests/test_btf_integration.py -v

These tests require:
- Root privileges (CAP_BPF, CAP_SYS_ADMIN)
- Compiled BPF programs in tests/bpf/
"""

import ctypes
from pathlib import Path

import tinybpf
from conftest import requires_root

pytestmark = requires_root


class TestBtfProperty:
    """Tests for BTF property on BpfObject."""

    def test_btf_property_exists(self, test_maps_bpf_path: Path) -> None:
        """BpfObject has btf property."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            # BTF should be available (CO-RE programs have BTF)
            btf = obj.btf
            # May or may not be None depending on build
            assert hasattr(obj, "btf")

    def test_btf_property_lazy_loaded(self, test_maps_bpf_path: Path) -> None:
        """BTF property is lazy-loaded."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            # First access
            btf1 = obj.btf
            # Second access should return same pointer
            btf2 = obj.btf
            assert btf1 is btf2


class TestBtfMapProperties:
    """Tests for BTF properties on BpfMap."""

    def test_btf_key_property(self, test_maps_bpf_path: Path) -> None:
        """BpfMap.btf_key returns BTF type info for key."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]
            btf_key = counters.btf_key

            # BTF must be present in our test files (compiled with -g)
            assert btf_key is not None, "BTF key info missing - test BPF file may not have BTF"
            assert isinstance(btf_key, tinybpf.BtfType)
            # Array keys are u32
            assert btf_key.kind == tinybpf.BtfKind.INT
            assert btf_key.size == 4

    def test_btf_value_property(self, test_maps_bpf_path: Path) -> None:
        """BpfMap.btf_value returns BTF type info for value."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]
            btf_value = counters.btf_value

            # BTF must be present in our test files (compiled with -g)
            assert btf_value is not None, "BTF value info missing - test BPF file may not have BTF"
            assert isinstance(btf_value, tinybpf.BtfType)
            # Array values are u64
            assert btf_value.kind == tinybpf.BtfKind.INT
            assert btf_value.size == 8

    def test_btf_properties_none_for_standalone(self, test_maps_bpf_path: Path) -> None:
        """BTF properties return None for standalone maps."""
        pin_path = "/sys/fs/bpf/tinybpf_btf_test"
        try:
            with tinybpf.load(test_maps_bpf_path) as obj:
                obj.maps["counters"].pin(pin_path)

            with tinybpf.open_pinned_map(pin_path) as pinned:
                # Standalone maps don't have BTF
                assert pinned.btf_key is None
                assert pinned.btf_value is None
        finally:
            p = Path(pin_path)
            if p.exists():
                p.unlink()


class TestTypedMethod:
    """Tests for BpfMap.typed() method."""

    def test_typed_returns_new_map(self, test_maps_bpf_path: Path) -> None:
        """typed() returns a new BpfMap instance."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]
            typed_counters = counters.typed(key=int, value=int)

            # Different instances
            assert typed_counters is not counters
            # Same underlying map
            assert typed_counters.fd == counters.fd

    def test_typed_auto_converts(self, test_maps_bpf_path: Path) -> None:
        """typed() map auto-converts on read."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"].typed(key=int, value=int)

            # Write using int
            counters[0] = 42

            # Read returns int
            result = counters[0]
            assert result == 42
            assert isinstance(result, int)

    def test_typed_iteration(self, test_maps_bpf_path: Path) -> None:
        """typed() map iteration returns typed values."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"].typed(key=int, value=int)

            # Set some values
            counters[0] = 10
            counters[1] = 20

            # keys() returns ints
            keys = list(counters.keys())
            assert all(isinstance(k, int) for k in keys)

            # values() returns ints
            values = list(counters.values())
            assert all(isinstance(v, int) for v in values)


class TestBtfAutoInference:
    """Tests for BTF auto-inference of primitive types."""

    def test_auto_inference_int_value(self, test_maps_bpf_path: Path) -> None:
        """Map auto-infers INT type from BTF for values."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # BTF must be present in our test files
            assert counters.btf_value is not None, "BTF required for auto-inference test"

            # Write a value using bytes (raw)
            counters[0] = (42).to_bytes(8, "little")

            # Read should auto-infer int from BTF
            result = counters[0]
            assert isinstance(result, int)
            assert result == 42

    def test_auto_inference_int_key(self, test_maps_bpf_path: Path) -> None:
        """Map auto-infers INT type from BTF for keys."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # BTF must be present in our test files
            assert counters.btf_key is not None, "BTF required for auto-inference test"

            # Write a value
            counters[0] = 100

            # Iterate over keys - should auto-infer int from BTF
            keys = list(counters.keys())
            assert all(isinstance(k, int) for k in keys)

    def test_auto_inference_with_iteration(self, test_maps_bpf_path: Path) -> None:
        """Map iteration auto-infers types from BTF."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # BTF must be present in our test files
            assert counters.btf_key is not None, "BTF required for auto-inference test"
            assert counters.btf_value is not None, "BTF required for auto-inference test"

            # Set some values
            counters[0] = 10
            counters[1] = 20

            # With BTF, items() should return (int, int) tuples
            for key, value in counters.items():
                assert isinstance(key, int)
                assert isinstance(value, int)

    def test_explicit_type_overrides_auto_inference(self, test_maps_bpf_path: Path) -> None:
        """Explicit .typed() call overrides auto-inference."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            counters[0] = 42

            # Auto-inference returns int (if BTF available)
            auto_result = counters[0]

            # Explicit typed() also returns int
            typed_counters = counters.typed(key=int, value=int)
            typed_result = typed_counters[0]

            assert typed_result == 42
            assert isinstance(typed_result, int)


class TestBtfInspection:
    """Tests for BTF inspection."""

    def test_btf_indicates_int_type(self, test_maps_bpf_path: Path) -> None:
        """BTF correctly indicates INT type for map values."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # BTF must be present in our test files
            btf_value = counters.btf_value
            assert btf_value is not None, "BTF required for this test"
            assert btf_value.kind == tinybpf.BtfKind.INT
            assert btf_value.size == 8  # __u64

            # With auto-inference, reading returns int
            counters[0] = 12345
            result = counters[0]
            assert isinstance(result, int)
            assert result == 12345

            # With explicit typing via .typed(), also returns int
            typed_counters = counters.typed(key=int, value=int)
            assert typed_counters[0] == 12345
            assert isinstance(typed_counters[0], int)


class TestRingBufferBtfValidation:
    """Tests for BTF validation in BpfRingBuffer.

    Note: BTF validation is best-effort. If the struct is not found in BTF,
    validation is silently skipped (graceful degradation). This matches the
    behavior when BTF is not available at all.
    """

    def test_ringbuf_accepts_event_type(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer accepts event type (gracefully skips validation if struct not in BTF)."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Define event type
            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # Should not raise - either matches BTF or validation is skipped
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=event,
            )
            rb.close()

    def test_ringbuf_accepts_event_type_with_different_name(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer accepts event type with PascalCase name."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Define event with different class name
            class Event(ctypes.Structure):  # PascalCase
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # Should work - validation is gracefully skipped if struct not found
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=Event,
            )
            rb.close()

    def test_ringbuf_btf_name_parameter(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer accepts btf_name parameter for explicit struct lookup."""
        with tinybpf.load(ringbuf_bpf_path) as obj:

            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # btf_name can be used to explicitly specify BTF struct name
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=Event,
                btf_name="event",
            )
            rb.close()

    def test_ringbuf_accepts_mismatched_type_gracefully(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer accepts mismatched type when struct not in BTF."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Define event with wrong size
            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    # Missing tid and comm - wrong size
                ]

            # Should NOT raise - validation is skipped when struct not in BTF
            # (The test BPF program's BTF doesn't include struct names)
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=event,
            )
            rb.close()


class TestPerfBufferBtfValidation:
    """Tests for BTF validation in BpfPerfBuffer.

    Note: BTF validation is best-effort. If the struct is not found in BTF,
    validation is silently skipped.
    """

    def test_perfbuf_accepts_event_type(self, perf_bpf_path: Path) -> None:
        """Perf buffer accepts event type."""
        with tinybpf.load(perf_bpf_path) as obj:
            # Define event type
            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("cpu", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            events_received: list[event] = []

            def handle_event(cpu: int, data: event) -> None:
                events_received.append(data)

            # Should not raise - validation is gracefully skipped if needed
            pb = tinybpf.BpfPerfBuffer(
                obj.maps["events"],
                handle_event,
                event_type=event,
            )
            pb.close()

    def test_perfbuf_accepts_btf_name_parameter(self, perf_bpf_path: Path) -> None:
        """Perf buffer accepts btf_name parameter."""
        with tinybpf.load(perf_bpf_path) as obj:

            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("cpu", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            def handle_event(cpu: int, data: Event) -> None:
                pass

            # btf_name can be used for explicit struct lookup
            pb = tinybpf.BpfPerfBuffer(
                obj.maps["events"],
                handle_event,
                event_type=Event,
                btf_name="event",
            )
            pb.close()


class TestRegisterType:
    """Tests for BpfObject.register_type().

    Note: register_type() is best-effort - if the struct is not found in BTF,
    the type is registered without validation.
    """

    def test_register_type_registers_type(self, ringbuf_bpf_path: Path) -> None:
        """register_type() registers Python type."""
        with tinybpf.load(ringbuf_bpf_path) as obj:

            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # Should succeed - registers without error
            obj.register_type("event", event)
            # Verify it's registered
            assert "event" in obj._type_registry


class TestGetBtfStructNames:
    """Tests for _get_btf_struct_names helper."""

    def test_get_struct_names_returns_list(self, ringbuf_bpf_path: Path) -> None:
        """_get_btf_struct_names returns a list."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # BTF must be present in our test files
            assert obj.btf is not None, "BTF required for this test"
            names = obj._get_btf_struct_names()
            assert isinstance(names, list)
            # Note: The list may be empty if BTF doesn't include
            # named struct definitions (common with some compile configs)


class TestGracefulDegradation:
    """Tests for graceful degradation when BTF is unavailable or incomplete."""

    def test_typed_works_without_btf(self, test_maps_bpf_path: Path) -> None:
        """typed() works even if BTF properties return None."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            # Even if BTF is not available, typed() should work
            counters = obj.maps["counters"].typed(key=int, value=int)

            counters[0] = 100
            assert counters[0] == 100

    def test_ringbuf_skips_validation_when_struct_not_in_btf(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer skips BTF validation gracefully when struct not in BTF."""
        with tinybpf.load(ringbuf_bpf_path) as obj:

            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # Should work - validation is skipped if struct not in BTF
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=event,
            )
            rb.close()

    def test_ringbuf_accepts_any_type_when_struct_not_in_btf(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer accepts any event type when struct not in BTF."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # This type has wrong size/fields, but validation is skipped
            class WrongEvent(ctypes.Structure):
                _fields_ = [("x", ctypes.c_uint64)]

            # Should work - no validation error
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=WrongEvent,
            )
            rb.close()
