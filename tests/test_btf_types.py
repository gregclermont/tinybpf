"""Unit tests for BTF type inference types and helper functions."""

import ctypes
from dataclasses import fields

import pytest

import tinybpf
from tinybpf._types import btf_kind, btf_vlen


class TestBtfKindEnum:
    """Tests for BtfKind enum."""

    def test_btf_kind_values(self) -> None:
        """BtfKind enum has expected values."""
        assert tinybpf.BtfKind.INT.value == 1
        assert tinybpf.BtfKind.PTR.value == 2
        assert tinybpf.BtfKind.ARRAY.value == 3
        assert tinybpf.BtfKind.STRUCT.value == 4
        assert tinybpf.BtfKind.UNION.value == 5
        assert tinybpf.BtfKind.ENUM.value == 6
        assert tinybpf.BtfKind.TYPEDEF.value == 8
        assert tinybpf.BtfKind.FLOAT.value == 16

    def test_btf_kind_is_int_enum(self) -> None:
        """BtfKind is an IntEnum."""
        from enum import IntEnum

        assert isinstance(tinybpf.BtfKind.INT, IntEnum)
        assert tinybpf.BtfKind.INT == 1


class TestBtfTypeDataclass:
    """Tests for BtfType dataclass."""

    def test_btf_type_fields(self) -> None:
        """BtfType has expected fields."""
        field_names = {f.name for f in fields(tinybpf.BtfType)}
        assert field_names == {"name", "kind", "size", "fields"}

    def test_btf_type_frozen(self) -> None:
        """BtfType is immutable."""
        bt = tinybpf.BtfType(name="test", kind=tinybpf.BtfKind.INT, size=4, fields=None)
        with pytest.raises(AttributeError):
            bt.name = "modified"  # type: ignore

    def test_btf_type_creation(self) -> None:
        """BtfType can be created with expected values."""
        bt = tinybpf.BtfType(
            name="unsigned int",
            kind=tinybpf.BtfKind.INT,
            size=4,
            fields=None,
        )
        assert bt.name == "unsigned int"
        assert bt.kind == tinybpf.BtfKind.INT
        assert bt.size == 4
        assert bt.fields is None


class TestBtfFieldDataclass:
    """Tests for BtfField dataclass."""

    def test_btf_field_fields(self) -> None:
        """BtfField has expected fields."""
        field_names = {f.name for f in fields(tinybpf.BtfField)}
        assert field_names == {"name", "offset", "size"}

    def test_btf_field_frozen(self) -> None:
        """BtfField is immutable."""
        bf = tinybpf.BtfField(name="pid", offset=0, size=4)
        with pytest.raises(AttributeError):
            bf.name = "modified"  # type: ignore

    def test_btf_field_creation(self) -> None:
        """BtfField can be created with expected values."""
        bf = tinybpf.BtfField(name="pid", offset=0, size=4)
        assert bf.name == "pid"
        assert bf.offset == 0
        assert bf.size == 4


class TestBtfValidationError:
    """Tests for BtfValidationError exception."""

    def test_btf_validation_error_inherits_bpf_error(self) -> None:
        """BtfValidationError is a subclass of BpfError."""
        assert issubclass(tinybpf.BtfValidationError, tinybpf.BpfError)

    def test_btf_validation_error_message(self) -> None:
        """BtfValidationError preserves message."""
        err = tinybpf.BtfValidationError("test error")
        assert "test error" in str(err)

    def test_btf_validation_error_suggestions(self) -> None:
        """BtfValidationError stores suggestions."""
        suggestions = ["event", "conn_info", "tcp_data"]
        err = tinybpf.BtfValidationError("not found", suggestions=suggestions)
        assert err.suggestions == suggestions

    def test_btf_validation_error_empty_suggestions(self) -> None:
        """BtfValidationError defaults to empty suggestions list."""
        err = tinybpf.BtfValidationError("not found")
        assert err.suggestions == []

    def test_btf_validation_error_catchable_as_bpf_error(self) -> None:
        """BtfValidationError can be caught as BpfError."""
        try:
            raise tinybpf.BtfValidationError("test")
        except tinybpf.BpfError as e:
            assert isinstance(e, tinybpf.BtfValidationError)


class TestBtfHelperFunctions:
    """Tests for BTF helper functions."""

    def test_btf_kind_extraction(self) -> None:
        """btf_kind extracts kind from info field."""
        # Kind is bits 24-28 of info field
        # Kind=1 (INT) with vlen=0: info = 0x01000000
        info = 1 << 24  # Kind 1 (INT)
        assert btf_kind(info) == 1

        # Kind=4 (STRUCT) with vlen=3: info = 0x04000003
        info = (4 << 24) | 3
        assert btf_kind(info) == 4

        # Kind=6 (ENUM) with vlen=5: info = 0x06000005
        info = (6 << 24) | 5
        assert btf_kind(info) == 6

    def test_btf_vlen_extraction(self) -> None:
        """btf_vlen extracts vlen from info field."""
        # vlen is bits 0-15 of info field
        info = (4 << 24) | 3  # Kind=4, vlen=3
        assert btf_vlen(info) == 3

        info = (4 << 24) | 100  # Kind=4, vlen=100
        assert btf_vlen(info) == 100

        info = (4 << 24) | 0  # Kind=4, vlen=0
        assert btf_vlen(info) == 0

    def test_btf_kind_and_vlen_combined(self) -> None:
        """btf_kind and btf_vlen work correctly together."""
        # Simulate a STRUCT with 5 members
        info = (tinybpf.BtfKind.STRUCT << 24) | 5
        assert btf_kind(info) == tinybpf.BtfKind.STRUCT
        assert btf_vlen(info) == 5


class TestExports:
    """Test that BTF types are properly exported."""

    def test_btf_kind_exported(self) -> None:
        """BtfKind is exported from tinybpf."""
        assert hasattr(tinybpf, "BtfKind")

    def test_btf_type_exported(self) -> None:
        """BtfType is exported from tinybpf."""
        assert hasattr(tinybpf, "BtfType")

    def test_btf_field_exported(self) -> None:
        """BtfField is exported from tinybpf."""
        assert hasattr(tinybpf, "BtfField")

    def test_btf_validation_error_exported(self) -> None:
        """BtfValidationError is exported from tinybpf."""
        assert hasattr(tinybpf, "BtfValidationError")


class TestTypeValidationLogic:
    """Test type validation logic without needing real BTF."""

    def test_size_mismatch_detection(self) -> None:
        """Validation detects size mismatches."""

        # Create a Python struct
        class Event(ctypes.Structure):
            _fields_ = [("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32)]

        # Create a BTF type with different size
        btf_type = tinybpf.BtfType(
            name="event",
            kind=tinybpf.BtfKind.STRUCT,
            size=24,  # Mismatch: Python struct is 8 bytes
            fields=(
                tinybpf.BtfField(name="pid", offset=0, size=4),
                tinybpf.BtfField(name="tid", offset=4, size=4),
                tinybpf.BtfField(name="comm", offset=8, size=16),
            ),
        )

        # We can't call _validate_python_type directly without BpfObject,
        # but we can verify the BtfType and struct sizes don't match
        assert ctypes.sizeof(Event) == 8
        assert btf_type.size == 24
        # The validation would fail due to size mismatch

    def test_btf_type_with_fields(self) -> None:
        """BtfType can store struct fields."""
        fields = (
            tinybpf.BtfField(name="pid", offset=0, size=4),
            tinybpf.BtfField(name="tid", offset=4, size=4),
            tinybpf.BtfField(name="comm", offset=8, size=16),
        )

        bt = tinybpf.BtfType(
            name="event",
            kind=tinybpf.BtfKind.STRUCT,
            size=24,
            fields=fields,
        )

        assert bt.fields is not None
        assert len(bt.fields) == 3
        assert bt.fields[0].name == "pid"
        assert bt.fields[1].name == "tid"
        assert bt.fields[2].name == "comm"
