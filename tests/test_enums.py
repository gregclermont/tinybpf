"""Tests for BPF enums."""

import pytest

from tinybpf.enums import MapType, MapUpdateFlags, ProgramType


class TestMapType:
    """Tests for MapType enum."""

    def test_common_types_exist(self) -> None:
        """Test that common map types are defined."""
        assert MapType.HASH == 1
        assert MapType.ARRAY == 2
        assert MapType.PERF_EVENT_ARRAY == 4
        assert MapType.RINGBUF == 27

    def test_type_names(self) -> None:
        """Test that type names are accessible."""
        assert MapType.HASH.name == "HASH"
        assert MapType.ARRAY.name == "ARRAY"

    def test_type_from_value(self) -> None:
        """Test creating type from integer value."""
        assert MapType(1) == MapType.HASH
        assert MapType(2) == MapType.ARRAY


class TestProgramType:
    """Tests for ProgramType enum."""

    def test_common_types_exist(self) -> None:
        """Test that common program types are defined."""
        assert ProgramType.KPROBE == 2
        assert ProgramType.TRACEPOINT == 5
        assert ProgramType.XDP == 6
        assert ProgramType.PERF_EVENT == 7

    def test_type_names(self) -> None:
        """Test that type names are accessible."""
        assert ProgramType.KPROBE.name == "KPROBE"
        assert ProgramType.TRACEPOINT.name == "TRACEPOINT"


class TestMapUpdateFlags:
    """Tests for MapUpdateFlags enum."""

    def test_flag_values(self) -> None:
        """Test that flag values are correct."""
        assert MapUpdateFlags.ANY == 0
        assert MapUpdateFlags.NOEXIST == 1
        assert MapUpdateFlags.EXIST == 2
        assert MapUpdateFlags.LOCK == 4

    def test_flags_can_be_used_as_int(self) -> None:
        """Test that flags can be converted to int."""
        assert int(MapUpdateFlags.ANY) == 0
        assert int(MapUpdateFlags.NOEXIST) == 1
