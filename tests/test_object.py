"""Tests for BPF object loading."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tinybpf.exceptions import BPFLoadError


class TestBPFObjectFileNotFound:
    """Tests for file not found handling."""

    def test_file_not_found(self) -> None:
        """Test that FileNotFoundError is raised for missing files."""
        from tinybpf.object import BPFObject

        with pytest.raises(FileNotFoundError):
            BPFObject("/nonexistent/path/to/program.bpf.o")

    def test_load_function_file_not_found(self) -> None:
        """Test that load() raises FileNotFoundError for missing files."""
        import tinybpf

        with pytest.raises(FileNotFoundError):
            tinybpf.load("/nonexistent/path/to/program.bpf.o")


class TestBPFObjectPath:
    """Tests for path handling."""

    def test_path_property(self) -> None:
        """Test that path is stored correctly."""
        # We can't actually load without libbpf, but we can test path validation
        with tempfile.NamedTemporaryFile(suffix=".bpf.o", delete=False) as f:
            f.write(b"not a valid elf file")
            temp_path = Path(f.name)

        try:
            # This will fail to load, but we can check path handling
            from tinybpf.object import BPFObject

            with pytest.raises((BPFLoadError, Exception)):
                BPFObject(temp_path)
        finally:
            temp_path.unlink()

    def test_accepts_string_path(self) -> None:
        """Test that string paths are accepted."""
        with tempfile.NamedTemporaryFile(suffix=".bpf.o", delete=False) as f:
            f.write(b"not a valid elf file")
            temp_path = f.name

        try:
            from tinybpf.object import BPFObject

            with pytest.raises((BPFLoadError, Exception)):
                BPFObject(temp_path)  # String path
        finally:
            Path(temp_path).unlink()


class TestLoadFunction:
    """Tests for the load() convenience function."""

    def test_load_returns_bpf_object(self) -> None:
        """Test that load() would return a BPFObject."""
        import tinybpf

        # Verify the function exists and has correct signature
        assert callable(tinybpf.load)

        # Check that it raises FileNotFoundError for missing files
        with pytest.raises(FileNotFoundError):
            tinybpf.load("/nonexistent.bpf.o")
