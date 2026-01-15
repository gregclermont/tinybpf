"""Test tinybpf API structure and imports."""

import os
import tempfile

import tinybpf


def test_exports():
    """All expected symbols are exported."""
    expected = [
        # Version functions
        "version",
        "init",
        "libbpf_version",
        # Main API
        "load",
        # Classes
        "BpfObject",
        "BpfProgram",
        "BpfMap",
        "BpfLink",
        # Collections
        "MapCollection",
        "ProgramCollection",
        # Data classes
        "MapInfo",
        "ProgramInfo",
        # Enums
        "BpfMapType",
        "BpfProgType",
        # Exceptions
        "BpfError",
        # Constants
        "BPF_ANY",
        "BPF_NOEXIST",
        "BPF_EXIST",
    ]
    for name in expected:
        assert hasattr(tinybpf, name), f"Missing export: {name}"


def test_map_type_enum():
    """BpfMapType enum has expected values."""
    assert tinybpf.BpfMapType.HASH == 1
    assert tinybpf.BpfMapType.ARRAY == 2
    assert tinybpf.BpfMapType.RINGBUF == 27


def test_prog_type_enum():
    """BpfProgType enum has expected values."""
    assert tinybpf.BpfProgType.KPROBE == 2
    assert tinybpf.BpfProgType.TRACEPOINT == 5
    assert tinybpf.BpfProgType.XDP == 6


def test_update_flags():
    """Update flag constants are correct."""
    assert tinybpf.BPF_ANY == 0
    assert tinybpf.BPF_NOEXIST == 1
    assert tinybpf.BPF_EXIST == 2


def test_bpf_error():
    """BpfError can be raised and caught."""
    try:
        raise tinybpf.BpfError("test error", errno=22)
    except tinybpf.BpfError as e:
        assert "test error" in str(e)
        assert e.errno == 22


def test_load_missing_file():
    """load() raises FileNotFoundError for missing files."""
    import pytest

    with pytest.raises(FileNotFoundError):
        tinybpf.load("/nonexistent/path/to/program.bpf.o")


def test_map_info_dataclass():
    """MapInfo is a frozen dataclass with expected fields."""
    from dataclasses import fields

    field_names = {f.name for f in fields(tinybpf.MapInfo)}
    assert field_names == {"name", "type", "key_size", "value_size", "max_entries"}


def test_program_info_dataclass():
    """ProgramInfo is a frozen dataclass with expected fields."""
    from dataclasses import fields

    field_names = {f.name for f in fields(tinybpf.ProgramInfo)}
    assert field_names == {"name", "section", "type"}


def test_load_invalid_elf():
    """Loading a non-ELF file should raise BpfError."""
    import pytest

    with tempfile.NamedTemporaryFile(suffix=".bpf.o", delete=False) as f:
        f.write(b"not an elf file")
        f.flush()
        try:
            with pytest.raises(tinybpf.BpfError):
                tinybpf.load(f.name)
        finally:
            os.unlink(f.name)


def test_load_truncated_elf():
    """Loading a truncated ELF should raise BpfError."""
    import pytest

    # ELF magic header but truncated
    with tempfile.NamedTemporaryFile(suffix=".bpf.o", delete=False) as f:
        f.write(b"\x7fELF\x02\x01\x01")  # Partial ELF header
        f.flush()
        try:
            with pytest.raises(tinybpf.BpfError):
                tinybpf.load(f.name)
        finally:
            os.unlink(f.name)
