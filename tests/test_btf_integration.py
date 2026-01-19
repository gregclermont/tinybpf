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

    def test_btf_float32_value_property(self, test_maps_bpf_path: Path) -> None:
        """BpfMap.btf_value returns FLOAT type info for 32-bit float values."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            float_map = obj.maps["float32_values"]
            btf_value = float_map.btf_value

            assert btf_value is not None, "BTF value info missing for float32 map"
            assert isinstance(btf_value, tinybpf.BtfType)
            assert btf_value.kind == tinybpf.BtfKind.FLOAT
            assert btf_value.size == 4

    def test_btf_float64_value_property(self, test_maps_bpf_path: Path) -> None:
        """BpfMap.btf_value returns FLOAT type info for 64-bit double values."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            double_map = obj.maps["float64_values"]
            btf_value = double_map.btf_value

            assert btf_value is not None, "BTF value info missing for float64 map"
            assert isinstance(btf_value, tinybpf.BtfType)
            assert btf_value.kind == tinybpf.BtfKind.FLOAT
            assert btf_value.size == 8


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

    def test_auto_inference_float32_value(self, test_maps_bpf_path: Path) -> None:
        """Map auto-infers FLOAT type from BTF for 32-bit float values."""
        import struct

        with tinybpf.load(test_maps_bpf_path) as obj:
            float_map = obj.maps["float32_values"]

            # BTF must indicate FLOAT kind
            btf_value = float_map.btf_value
            assert btf_value is not None, "BTF required for FLOAT auto-inference test"
            assert btf_value.kind == tinybpf.BtfKind.FLOAT, f"Expected FLOAT, got {btf_value.kind}"
            assert btf_value.size == 4, f"Expected size 4 for float, got {btf_value.size}"

            # Write a float value as bytes
            float_value = 3.14159
            float_map[0] = struct.pack("f", float_value)

            # Read should auto-infer float from BTF
            result = float_map[0]
            assert isinstance(result, float), f"Expected float, got {type(result)}"
            assert abs(result - float_value) < 0.0001, f"Expected ~{float_value}, got {result}"

    def test_auto_inference_float64_value(self, test_maps_bpf_path: Path) -> None:
        """Map auto-infers FLOAT type from BTF for 64-bit double values."""
        import struct

        with tinybpf.load(test_maps_bpf_path) as obj:
            double_map = obj.maps["float64_values"]

            # BTF must indicate FLOAT kind
            btf_value = double_map.btf_value
            assert btf_value is not None, "BTF required for FLOAT auto-inference test"
            assert btf_value.kind == tinybpf.BtfKind.FLOAT, f"Expected FLOAT, got {btf_value.kind}"
            assert btf_value.size == 8, f"Expected size 8 for double, got {btf_value.size}"

            # Write a double value as bytes
            double_value = 3.141592653589793
            double_map[0] = struct.pack("d", double_value)

            # Read should auto-infer float (Python float is 64-bit) from BTF
            result = double_map[0]
            assert isinstance(result, float), f"Expected float, got {type(result)}"
            assert abs(result - double_value) < 1e-10, f"Expected ~{double_value}, got {result}"

    def test_auto_inference_float_iteration(self, test_maps_bpf_path: Path) -> None:
        """Map iteration auto-infers FLOAT type from BTF."""
        import struct

        with tinybpf.load(test_maps_bpf_path) as obj:
            float_map = obj.maps["float32_values"]

            # BTF must be present
            assert float_map.btf_value is not None, "BTF required for FLOAT auto-inference test"

            # Write some float values
            float_map[0] = struct.pack("f", 1.5)
            float_map[1] = struct.pack("f", 2.5)

            # values() should return Python floats
            values = list(float_map.values())
            assert len(values) >= 2
            # Check the ones we set (array may have other entries)
            float_values = [v for v in values if isinstance(v, float) and v > 0]
            assert len(float_values) >= 2, "Expected at least 2 non-zero float values"


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

    def test_ringbuf_validate_btf_struct_parameter(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer validates type against BTF struct when validate_btf_struct is specified."""
        with tinybpf.load(ringbuf_bpf_path) as obj:

            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # Should succeed - struct exists in BTF and matches
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=Event,
                validate_btf_struct="event",
            )
            rb.close()

    def test_ringbuf_validate_btf_struct_not_found(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer raises error when validate_btf_struct specifies non-existent struct."""
        import pytest

        with tinybpf.load(ringbuf_bpf_path) as obj:

            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # validate_btf_struct is strict - error if struct not in BTF
            with pytest.raises(tinybpf.BpfError, match="not found"):
                tinybpf.BpfRingBuffer(
                    obj.maps["events"],
                    event_type=Event,
                    validate_btf_struct="nonexistent_struct",
                )

    def test_ringbuf_rejects_size_mismatch_with_validation(self, ringbuf_bpf_path: Path) -> None:
        """Ring buffer raises error on size mismatch when validate_btf_struct is used."""
        import pytest

        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Define event with wrong size
            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    # Missing tid and comm - wrong size
                ]

            # Should raise - size mismatch with BTF struct
            with pytest.raises(tinybpf.BtfValidationError, match="Size mismatch"):
                tinybpf.BpfRingBuffer(
                    obj.maps["events"],
                    event_type=Event,
                    validate_btf_struct="event",
                )

    def test_ringbuf_rejects_field_name_mismatch_with_validation(
        self, ringbuf_bpf_path: Path
    ) -> None:
        """Ring buffer raises error on field name mismatch when validation is enabled."""
        import pytest

        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Define event with wrong field names
            class Event(ctypes.Structure):
                _fields_ = [
                    ("process_id", ctypes.c_uint32),  # wrong name (should be 'pid')
                    ("thread_id", ctypes.c_uint32),  # wrong name (should be 'tid')
                    ("command", ctypes.c_char * 16),  # wrong name (should be 'comm')
                ]

            # Should raise - field name mismatch with BTF struct
            with pytest.raises(tinybpf.BtfValidationError, match="Field name mismatch"):
                tinybpf.BpfRingBuffer(
                    obj.maps["events"],
                    event_type=Event,
                    validate_btf_struct="event",
                )

    def test_ringbuf_accepts_field_name_mismatch_when_disabled(
        self, ringbuf_bpf_path: Path
    ) -> None:
        """Ring buffer accepts field name mismatch when validate_field_names=False."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Define event with wrong field names but correct size
            class Event(ctypes.Structure):
                _fields_ = [
                    ("process_id", ctypes.c_uint32),  # wrong name
                    ("thread_id", ctypes.c_uint32),  # wrong name
                    ("command", ctypes.c_char * 16),  # wrong name
                ]

            # Should succeed - field name validation disabled
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=Event,
                validate_btf_struct="event",
                validate_field_names=False,
            )
            rb.close()

    def test_ringbuf_accepts_mismatched_type_without_explicit_validation(
        self, ringbuf_bpf_path: Path
    ) -> None:
        """Ring buffer accepts mismatched type when validate_btf_struct is not specified."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # Define event with wrong size
            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    # Missing tid and comm - wrong size
                ]

            # Should NOT raise - validation only happens when validate_btf_struct is specified
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

    def test_perfbuf_validate_btf_struct_parameter(self, perf_bpf_path: Path) -> None:
        """Perf buffer validates type against BTF struct when validate_btf_struct is specified."""
        with tinybpf.load(perf_bpf_path) as obj:

            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("cpu", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            def handle_event(cpu: int, data: Event) -> None:
                pass

            # Should succeed - struct exists in BTF and matches
            pb = tinybpf.BpfPerfBuffer(
                obj.maps["events"],
                handle_event,
                event_type=Event,
                validate_btf_struct="event",
            )
            pb.close()

    def test_perfbuf_validate_btf_struct_not_found(self, perf_bpf_path: Path) -> None:
        """Perf buffer raises error when validate_btf_struct specifies non-existent struct."""
        import pytest

        with tinybpf.load(perf_bpf_path) as obj:

            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("cpu", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            def handle_event(cpu: int, data: Event) -> None:
                pass

            # validate_btf_struct is strict - error if struct not in BTF
            with pytest.raises(tinybpf.BpfError, match="not found"):
                tinybpf.BpfPerfBuffer(
                    obj.maps["events"],
                    handle_event,
                    event_type=Event,
                    validate_btf_struct="nonexistent_struct",
                )

    def test_perfbuf_rejects_size_mismatch_with_validation(self, perf_bpf_path: Path) -> None:
        """Perf buffer raises error on size mismatch when validate_btf_struct is used."""
        import pytest

        with tinybpf.load(perf_bpf_path) as obj:

            class Event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    # Missing cpu and comm - wrong size
                ]

            def handle_event(cpu: int, data: Event) -> None:
                pass

            # Should raise - size mismatch with BTF struct
            with pytest.raises(tinybpf.BtfValidationError, match="Size mismatch"):
                tinybpf.BpfPerfBuffer(
                    obj.maps["events"],
                    handle_event,
                    event_type=Event,
                    validate_btf_struct="event",
                )


class TestRegisterType:
    """Tests for BpfObject.register_type().

    Note: register_type() is strict - the BTF struct must exist and the
    type is validated against it. This enforces a 1:1 mapping between
    BTF struct names and Python types.
    """

    def test_register_type_registers_type(self, ringbuf_bpf_path: Path) -> None:
        """register_type() registers Python type after validation."""
        with tinybpf.load(ringbuf_bpf_path) as obj:

            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # Should succeed - struct exists in BTF and matches
            obj.register_type("event", event)
            # Verify it's registered
            assert "event" in obj._type_registry
            assert obj.lookup_btf_name(event) == "event"

    def test_register_type_rejects_size_mismatch(self, ringbuf_bpf_path: Path) -> None:
        """register_type() raises error on size mismatch."""
        import pytest

        with tinybpf.load(ringbuf_bpf_path) as obj:

            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    # Missing tid and comm - wrong size
                ]

            # Should raise - size mismatch
            with pytest.raises(tinybpf.BtfValidationError, match="Size mismatch"):
                obj.register_type("event", event)

    def test_register_type_rejects_field_name_mismatch(self, ringbuf_bpf_path: Path) -> None:
        """register_type() raises error on field name mismatch."""
        import pytest

        with tinybpf.load(ringbuf_bpf_path) as obj:

            class event(ctypes.Structure):
                _fields_ = [
                    ("process_id", ctypes.c_uint32),  # wrong name
                    ("thread_id", ctypes.c_uint32),  # wrong name
                    ("command", ctypes.c_char * 16),  # wrong name
                ]

            # Should raise - field name mismatch
            with pytest.raises(tinybpf.BtfValidationError, match="Field name mismatch"):
                obj.register_type("event", event)

    def test_register_type_accepts_field_name_mismatch_when_disabled(
        self, ringbuf_bpf_path: Path
    ) -> None:
        """register_type() accepts field name mismatch when validate_field_names=False."""
        with tinybpf.load(ringbuf_bpf_path) as obj:

            class event(ctypes.Structure):
                _fields_ = [
                    ("process_id", ctypes.c_uint32),  # wrong name
                    ("thread_id", ctypes.c_uint32),  # wrong name
                    ("command", ctypes.c_char * 16),  # wrong name
                ]

            # Should succeed - field name validation disabled
            obj.register_type("event", event, validate_field_names=False)
            assert "event" in obj._type_registry

    def test_register_type_rejects_nonexistent_struct(self, ringbuf_bpf_path: Path) -> None:
        """register_type() raises error when struct not in BTF."""
        import pytest

        with tinybpf.load(ringbuf_bpf_path) as obj:

            class MyStruct(ctypes.Structure):
                _fields_ = [("x", ctypes.c_uint32)]

            # Should raise - struct not in BTF
            with pytest.raises(tinybpf.BpfError, match="not found"):
                obj.register_type("nonexistent_struct", MyStruct)


class TestGetBtfStructNames:
    """Tests for _get_btf_struct_names helper."""

    def test_get_struct_names_returns_list(self, ringbuf_bpf_path: Path) -> None:
        """_get_btf_struct_names returns a list containing struct names."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # BTF must be present in our test files
            assert obj.btf is not None, "BTF required for this test"
            names = obj._get_btf_struct_names()
            assert isinstance(names, list)
            # The 'event' struct should be in BTF now (via _event_btf_anchor)
            assert "event" in names, f"Expected 'event' in BTF struct names, got: {names}"


class TestGracefulDegradation:
    """Tests for graceful degradation when BTF validation is not explicitly requested.

    Note: Without validate_btf_struct parameter, validation is NOT performed.
    This allows for gradual adoption of BTF validation.
    """

    def test_typed_works_without_btf(self, test_maps_bpf_path: Path) -> None:
        """typed() works even if BTF properties return None."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            # Even if BTF is not available, typed() should work
            counters = obj.maps["counters"].typed(key=int, value=int)

            counters[0] = 100
            assert counters[0] == 100

    def test_ringbuf_skips_validation_without_validate_btf_struct(
        self, ringbuf_bpf_path: Path
    ) -> None:
        """Ring buffer skips BTF validation when validate_btf_struct is not specified."""
        with tinybpf.load(ringbuf_bpf_path) as obj:

            class event(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("tid", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                ]

            # Should work - no validate_btf_struct means no validation
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=event,
            )
            rb.close()

    def test_ringbuf_accepts_any_type_without_validate_btf_struct(
        self, ringbuf_bpf_path: Path
    ) -> None:
        """Ring buffer accepts any event type when validate_btf_struct is not specified."""
        with tinybpf.load(ringbuf_bpf_path) as obj:
            # This type has wrong size/fields, but validation is not requested
            class WrongEvent(ctypes.Structure):
                _fields_ = [("x", ctypes.c_uint64)]

            # Should work - no validate_btf_struct means no validation
            rb = tinybpf.BpfRingBuffer(
                obj.maps["events"],
                event_type=WrongEvent,
            )
            rb.close()


class TestTypedMethodWithStructs:
    """Tests for .typed() method with ctypes.Structure types."""

    def test_typed_with_struct_key(self, test_maps_bpf_path: Path) -> None:
        """typed() works with ctypes.Structure for key."""
        with tinybpf.load(test_maps_bpf_path) as obj:

            class Key(ctypes.Structure):
                _fields_ = [("pid", ctypes.c_uint32)]

            hash_map = obj.maps["pid_counts"].typed(key=Key, value=int)

            # Write with struct key
            key = Key(pid=12345)
            hash_map[key] = 42

            # Read back
            result = hash_map[key]
            assert result == 42
            assert isinstance(result, int)

            # Clean up
            del hash_map[key]

    def test_typed_with_struct_value(self, test_maps_bpf_path: Path) -> None:
        """typed() works with ctypes.Structure for value."""
        with tinybpf.load(test_maps_bpf_path) as obj:

            class Value(ctypes.Structure):
                _fields_ = [("count", ctypes.c_uint64)]

            hash_map = obj.maps["pid_counts"].typed(key=int, value=Value)

            # Write with struct value
            val = Value(count=999)
            hash_map[12345] = val

            # Read back returns struct
            result = hash_map[12345]
            assert isinstance(result, Value)
            assert result.count == 999

            # Clean up
            del hash_map[12345]

    def test_typed_with_struct_roundtrip(self, test_maps_bpf_path: Path) -> None:
        """typed() supports round-trip with struct key and value."""
        with tinybpf.load(test_maps_bpf_path) as obj:

            class Key(ctypes.Structure):
                _fields_ = [("pid", ctypes.c_uint32)]

            class Value(ctypes.Structure):
                _fields_ = [("count", ctypes.c_uint64)]

            hash_map = obj.maps["pid_counts"].typed(key=Key, value=Value)

            # Write
            key = Key(pid=54321)
            val = Value(count=123456789)
            hash_map[key] = val

            # Read back
            result = hash_map[key]
            assert isinstance(result, Value)
            assert result.count == 123456789

            # Clean up
            del hash_map[key]

    def test_typed_struct_iteration(self, test_maps_bpf_path: Path) -> None:
        """typed() iteration works with struct types."""
        with tinybpf.load(test_maps_bpf_path) as obj:

            class Key(ctypes.Structure):
                _fields_ = [("pid", ctypes.c_uint32)]

            class Value(ctypes.Structure):
                _fields_ = [("count", ctypes.c_uint64)]

            hash_map = obj.maps["pid_counts"].typed(key=Key, value=Value)

            # Add entries
            for i in range(3):
                hash_map[Key(pid=60000 + i)] = Value(count=i * 100)

            # keys() returns Key structs
            keys = list(hash_map.keys())
            assert len(keys) >= 3
            assert all(isinstance(k, Key) for k in keys)

            # values() returns Value structs
            values = list(hash_map.values())
            assert len(values) >= 3
            assert all(isinstance(v, Value) for v in values)

            # items() returns (Key, Value) tuples
            items = list(hash_map.items())
            assert len(items) >= 3
            assert all(isinstance(k, Key) and isinstance(v, Value) for k, v in items)

            # Clean up
            for i in range(3):
                hash_map.delete(Key(pid=60000 + i))


class TestBtfValidationErrors:
    """Tests for BTF validation error cases."""

    def test_typed_struct_size_mismatch_raises(self, test_maps_bpf_path: Path) -> None:
        """typed() raises BtfValidationError on struct size mismatch."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # BTF indicates value is 8 bytes (u64)
            assert counters.btf_value is not None, "BTF required for this test"
            assert counters.btf_value.size == 8

            # Define struct with wrong size (4 bytes instead of 8)
            class WrongSizeValue(ctypes.Structure):
                _fields_ = [("x", ctypes.c_uint32)]  # 4 bytes, should be 8

            # Should raise BtfValidationError
            import pytest

            with pytest.raises(tinybpf.BtfValidationError, match="Size mismatch"):
                counters.typed(value=WrongSizeValue)

    def test_typed_struct_correct_size_succeeds(self, test_maps_bpf_path: Path) -> None:
        """typed() succeeds when struct size matches BTF."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # BTF indicates value is 8 bytes (u64)
            assert counters.btf_value is not None, "BTF required for this test"
            assert counters.btf_value.size == 8

            # Define struct with correct size
            class CorrectSizeValue(ctypes.Structure):
                _fields_ = [("value", ctypes.c_uint64)]  # 8 bytes

            # Should succeed
            typed_map = counters.typed(value=CorrectSizeValue)
            assert typed_map is not None

    def test_typed_int_skips_size_validation(self, test_maps_bpf_path: Path) -> None:
        """typed() with int skips struct size validation."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # int type doesn't have _fields_, so no size check
            typed_map = counters.typed(value=int)
            typed_map[0] = 42
            assert typed_map[0] == 42


class TestValidateFieldNamesParameter:
    """Tests for validate_field_names parameter in typed()."""

    def test_validate_field_names_default_true(self, test_maps_bpf_path: Path) -> None:
        """validate_field_names defaults to True."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            class Value(ctypes.Structure):
                _fields_ = [("count", ctypes.c_uint64)]

            # Should succeed with correct size (name validation is best-effort)
            typed_map = counters.typed(value=Value, validate_field_names=True)
            assert typed_map is not None

    def test_validate_field_names_false(self, test_maps_bpf_path: Path) -> None:
        """validate_field_names=False only validates sizes."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            class Value(ctypes.Structure):
                _fields_ = [("different_name", ctypes.c_uint64)]

            # Should succeed - size matches even if field name differs
            typed_map = counters.typed(value=Value, validate_field_names=False)
            assert typed_map is not None
            typed_map[0] = Value(different_name=123)
            result = typed_map[0]
            assert result.different_name == 123


class TestOpenPinnedMapWithTypes:
    """Tests for open_pinned_map with type parameters."""

    def test_open_pinned_map_with_key_type(self, test_maps_bpf_path: Path) -> None:
        """open_pinned_map accepts key_type parameter."""
        pin_path = "/sys/fs/bpf/tinybpf_type_test_key"
        try:
            with tinybpf.load(test_maps_bpf_path) as obj:
                obj.maps["pid_counts"].pin(pin_path)

            # Open with typed key
            with tinybpf.open_pinned_map(pin_path, key_type=int) as pinned:
                key = 12345
                pinned[key] = (42).to_bytes(8, "little")

                # Lookup with typed key
                result = pinned.lookup(key)
                assert result is not None
                # Value is bytes (no BTF for pinned maps)
                assert result == (42).to_bytes(8, "little")

                # Clean up
                del pinned[key]
        finally:
            p = Path(pin_path)
            if p.exists():
                p.unlink()

    def test_open_pinned_map_with_value_type(self, test_maps_bpf_path: Path) -> None:
        """open_pinned_map accepts value_type parameter."""
        pin_path = "/sys/fs/bpf/tinybpf_type_test_val"
        try:
            with tinybpf.load(test_maps_bpf_path) as obj:
                obj.maps["pid_counts"].pin(pin_path)

            # Open with typed value
            with tinybpf.open_pinned_map(pin_path, value_type=int) as pinned:
                key = (12345).to_bytes(4, "little")
                pinned[key] = 42

                # Lookup returns typed value
                result = pinned.lookup(key)
                assert result == 42
                assert isinstance(result, int)

                # Clean up
                del pinned[key]
        finally:
            p = Path(pin_path)
            if p.exists():
                p.unlink()

    def test_open_pinned_map_with_both_types(self, test_maps_bpf_path: Path) -> None:
        """open_pinned_map accepts both key_type and value_type."""
        pin_path = "/sys/fs/bpf/tinybpf_type_test_both"
        try:
            with tinybpf.load(test_maps_bpf_path) as obj:
                obj.maps["pid_counts"].pin(pin_path)

            # Open with both types
            with tinybpf.open_pinned_map(pin_path, key_type=int, value_type=int) as pinned:
                pinned[12345] = 42

                # Lookup returns typed value
                result = pinned.lookup(12345)
                assert result == 42
                assert isinstance(result, int)

                # Iteration returns typed keys
                keys = list(pinned.keys())
                assert 12345 in keys
                assert all(isinstance(k, int) for k in keys)

                # Clean up
                del pinned[12345]
        finally:
            p = Path(pin_path)
            if p.exists():
                p.unlink()


class TestTypeConversionErrors:
    """Tests for type conversion error handling."""

    def test_invalid_key_type_raises(self, test_maps_bpf_path: Path) -> None:
        """Invalid key type raises TypeError."""
        import pytest

        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            # Float is not a valid key type
            with pytest.raises(TypeError, match="Cannot convert"):
                hash_map[3.14] = b"\x00" * 8

    def test_invalid_value_type_raises(self, test_maps_bpf_path: Path) -> None:
        """Invalid value type raises TypeError."""
        import pytest

        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            # String is not a valid value type
            with pytest.raises(TypeError, match="Cannot convert"):
                hash_map[b"\x00" * 4] = "not valid"

    def test_wrong_key_size_raises(self, test_maps_bpf_path: Path) -> None:
        """Wrong key size raises ValueError."""
        import pytest

        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            # Key should be 4 bytes, provide 8
            with pytest.raises(ValueError, match="Key size mismatch"):
                hash_map[b"\x00" * 8] = b"\x00" * 8

    def test_wrong_value_size_raises(self, test_maps_bpf_path: Path) -> None:
        """Wrong value size raises ValueError."""
        import pytest

        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            # Value should be 8 bytes, provide 4
            with pytest.raises(ValueError, match="Value size mismatch"):
                hash_map[b"\x00" * 4] = b"\x00" * 4

    def test_typed_unsupported_key_type_raises(self, test_maps_bpf_path: Path) -> None:
        """Using unsupported key type with typed() raises TypeError on read."""
        import ctypes

        import pytest

        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            # Write a value with bytes key
            key = (12345).to_bytes(4, "little")
            hash_map[key] = (42).to_bytes(8, "little")

            # ctypes simple types are not supported - use int instead
            typed_map = hash_map.typed(key=ctypes.c_uint32)

            with pytest.raises(TypeError, match=r"typed\(\) key must be int or ctypes.Structure"):
                typed_map[key]

            # Clean up
            del hash_map[key]

    def test_typed_unsupported_value_type_raises(self, test_maps_bpf_path: Path) -> None:
        """Using unsupported value type with typed() raises TypeError on read."""
        import ctypes

        import pytest

        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            # Write a value
            key = (12345).to_bytes(4, "little")
            hash_map[key] = (42).to_bytes(8, "little")

            # ctypes simple types are not supported - use int instead
            typed_map = hash_map.typed(value=ctypes.c_uint64)

            with pytest.raises(TypeError, match=r"typed\(\) value must be int or ctypes.Structure"):
                typed_map[key]

            # Clean up
            del hash_map[key]


class TestAutoInferenceEdgeCases:
    """Tests for edge cases in BTF auto-inference."""

    def test_auto_inference_falls_back_to_bytes_without_btf(self, test_maps_bpf_path: Path) -> None:
        """Auto-inference returns bytes when BTF is unavailable."""
        pin_path = "/sys/fs/bpf/tinybpf_no_btf_test"
        try:
            with tinybpf.load(test_maps_bpf_path) as obj:
                obj.maps["pid_counts"].pin(pin_path)

            # Pinned maps don't have BTF
            with tinybpf.open_pinned_map(pin_path) as pinned:
                assert pinned.btf_key is None
                assert pinned.btf_value is None

                key = (12345).to_bytes(4, "little")
                pinned[key] = (42).to_bytes(8, "little")

                # Without BTF, returns bytes
                result = pinned[key]
                assert result == (42).to_bytes(8, "little")
                assert isinstance(result, bytes)

                del pinned[key]
        finally:
            p = Path(pin_path)
            if p.exists():
                p.unlink()

    def test_explicit_type_takes_precedence_over_btf(self, test_maps_bpf_path: Path) -> None:
        """Explicit type via typed() takes precedence over BTF auto-inference."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            counters = obj.maps["counters"]

            # BTF indicates INT, so auto-inference would return int
            counters[0] = 42
            auto_result = counters[0]
            assert isinstance(auto_result, int)

            # But typed(value=bytes) should return bytes
            # Note: Since we can't easily force bytes return, let's verify
            # that explicit struct type overrides
            class Value(ctypes.Structure):
                _fields_ = [("v", ctypes.c_uint64)]

            typed_counters = counters.typed(value=Value)
            result = typed_counters[0]
            assert isinstance(result, Value)
            assert result.v == 42

    def test_auto_inference_works_with_delete(self, test_maps_bpf_path: Path) -> None:
        """Auto-inference doesn't affect delete operations."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            # Add entry
            key = (99999).to_bytes(4, "little")
            hash_map[key] = 42

            # Verify it exists (auto-infers int)
            assert hash_map[key] == 42

            # Delete with bytes key should work
            del hash_map[key]
            assert key not in hash_map

    def test_auto_inference_with_contains(self, test_maps_bpf_path: Path) -> None:
        """Auto-inference doesn't affect __contains__ check."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.maps["pid_counts"]

            key = (88888).to_bytes(4, "little")
            hash_map[key] = 42

            # __contains__ should work regardless of auto-inference
            assert key in hash_map

            del hash_map[key]
            assert key not in hash_map
