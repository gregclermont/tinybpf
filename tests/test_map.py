"""Tests for BPF map classes."""

import ctypes
import struct
from unittest.mock import MagicMock, patch

import pytest

from tinybpf.enums import MapType
from tinybpf.map import MapInfo, TypedBPFMap


class TestMapInfo:
    """Tests for MapInfo dataclass."""

    def test_create_map_info(self) -> None:
        """Test creating MapInfo."""
        info = MapInfo(
            name="test_map",
            type=MapType.HASH,
            key_size=4,
            value_size=8,
            max_entries=1024,
            fd=5,
        )
        assert info.name == "test_map"
        assert info.type == MapType.HASH
        assert info.key_size == 4
        assert info.value_size == 8
        assert info.max_entries == 1024
        assert info.fd == 5

    def test_type_name(self) -> None:
        """Test type_name property."""
        info = MapInfo(
            name="test",
            type=MapType.ARRAY,
            key_size=4,
            value_size=4,
            max_entries=16,
            fd=1,
        )
        assert info.type_name == "ARRAY"

    def test_frozen(self) -> None:
        """Test that MapInfo is immutable."""
        info = MapInfo(
            name="test",
            type=MapType.HASH,
            key_size=4,
            value_size=8,
            max_entries=100,
            fd=1,
        )
        with pytest.raises(Exception):  # FrozenInstanceError
            info.name = "changed"  # type: ignore


class TestTypedBPFMapSerialization:
    """Tests for TypedBPFMap serialization logic."""

    def test_struct_format_validation(self) -> None:
        """Test that struct format size is validated."""
        mock_map = MagicMock()
        mock_map.key_size = 4
        mock_map.value_size = 8

        # This should work - sizes match
        typed = TypedBPFMap(mock_map, key_format="I", value_format="Q")
        assert typed._key_format == "I"
        assert typed._value_format == "Q"

    def test_struct_format_size_mismatch(self) -> None:
        """Test that size mismatch raises ValueError."""
        mock_map = MagicMock()
        mock_map.key_size = 4
        mock_map.value_size = 8

        # Key format "Q" is 8 bytes, but key_size is 4
        with pytest.raises(ValueError, match="key size"):
            TypedBPFMap(mock_map, key_format="Q", value_format="Q")

        # Value format "I" is 4 bytes, but value_size is 8
        with pytest.raises(ValueError, match="value size"):
            TypedBPFMap(mock_map, key_format="I", value_format="I")

    def test_serialize_key_struct_format(self) -> None:
        """Test key serialization with struct format."""
        mock_map = MagicMock()
        mock_map.key_size = 4
        mock_map.value_size = 8

        typed = TypedBPFMap(mock_map, key_format="I", value_format="Q")

        # Serialize an integer key
        result = typed._serialize_key(42)
        assert result == struct.pack("I", 42)

    def test_serialize_key_tuple(self) -> None:
        """Test key serialization with tuple."""
        mock_map = MagicMock()
        mock_map.key_size = 8  # Two 4-byte integers
        mock_map.value_size = 8

        typed = TypedBPFMap(mock_map, key_format="II", value_format="Q")

        # Serialize a tuple key
        result = typed._serialize_key((1, 2))
        assert result == struct.pack("II", 1, 2)

    def test_deserialize_key_single_value(self) -> None:
        """Test key deserialization returns single value for single-element format."""
        mock_map = MagicMock()
        mock_map.key_size = 4
        mock_map.value_size = 8

        typed = TypedBPFMap(mock_map, key_format="I", value_format="Q")

        data = struct.pack("I", 42)
        result = typed._deserialize_key(data)
        assert result == 42  # Single value, not tuple

    def test_deserialize_key_tuple(self) -> None:
        """Test key deserialization returns tuple for multi-element format."""
        mock_map = MagicMock()
        mock_map.key_size = 8
        mock_map.value_size = 8

        typed = TypedBPFMap(mock_map, key_format="II", value_format="Q")

        data = struct.pack("II", 1, 2)
        result = typed._deserialize_key(data)
        assert result == (1, 2)

    def test_serialize_value_struct_format(self) -> None:
        """Test value serialization with struct format."""
        mock_map = MagicMock()
        mock_map.key_size = 4
        mock_map.value_size = 8

        typed = TypedBPFMap(mock_map, key_format="I", value_format="Q")

        result = typed._serialize_value(12345678901234)
        assert result == struct.pack("Q", 12345678901234)

    def test_raw_property(self) -> None:
        """Test that raw property returns underlying map."""
        mock_map = MagicMock()
        mock_map.key_size = 4
        mock_map.value_size = 8

        typed = TypedBPFMap(mock_map, key_format="I", value_format="Q")
        assert typed.raw is mock_map

    def test_ctypes_structure_validation(self) -> None:
        """Test validation with ctypes structures."""

        class TestKey(ctypes.Structure):
            _fields_ = [("value", ctypes.c_uint32)]

        mock_map = MagicMock()
        mock_map.key_size = 4
        mock_map.value_size = 8

        # This should work - sizes match
        typed = TypedBPFMap(mock_map, key_type=TestKey, value_format="Q")
        assert typed._key_type is TestKey

    def test_ctypes_structure_size_mismatch(self) -> None:
        """Test that ctypes structure size mismatch raises ValueError."""

        class TestKey(ctypes.Structure):
            _fields_ = [("value", ctypes.c_uint64)]  # 8 bytes

        mock_map = MagicMock()
        mock_map.key_size = 4  # But map expects 4 bytes
        mock_map.value_size = 8

        with pytest.raises(ValueError, match="key size"):
            TypedBPFMap(mock_map, key_type=TestKey, value_format="Q")
