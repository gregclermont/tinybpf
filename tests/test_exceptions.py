"""Tests for BPF exceptions."""

import pytest

from tinybpf.exceptions import (
    BPFAttachError,
    BPFError,
    BPFLoadError,
    BPFMapError,
    BPFNotFoundError,
    BPFPermissionError,
    BPFSyscallError,
    BPFVerifierError,
)


class TestBPFError:
    """Tests for base BPFError."""

    def test_basic_error(self) -> None:
        """Test creating a basic error."""
        err = BPFError("test error")
        assert str(err) == "test error"

    def test_inheritance(self) -> None:
        """Test that BPFError is an Exception."""
        assert issubclass(BPFError, Exception)


class TestBPFLoadError:
    """Tests for BPFLoadError."""

    def test_basic_error(self) -> None:
        """Test creating a load error."""
        err = BPFLoadError("failed to load")
        assert str(err) == "failed to load"
        assert isinstance(err, BPFError)


class TestBPFVerifierError:
    """Tests for BPFVerifierError."""

    def test_with_log(self) -> None:
        """Test creating a verifier error with log."""
        err = BPFVerifierError("verifier failed", verifier_log="R0 is not a pointer")
        assert "verifier failed" in str(err)
        assert err.verifier_log == "R0 is not a pointer"

    def test_without_log(self) -> None:
        """Test creating a verifier error without log."""
        err = BPFVerifierError("verifier failed")
        assert err.verifier_log is None


class TestBPFAttachError:
    """Tests for BPFAttachError."""

    def test_basic_error(self) -> None:
        """Test creating an attach error."""
        err = BPFAttachError("failed to attach kprobe")
        assert "attach" in str(err).lower() or "kprobe" in str(err)
        assert isinstance(err, BPFError)


class TestBPFMapError:
    """Tests for BPFMapError."""

    def test_basic_error(self) -> None:
        """Test creating a map error."""
        err = BPFMapError("map lookup failed")
        assert "map" in str(err).lower() or "lookup" in str(err)
        assert isinstance(err, BPFError)


class TestBPFNotFoundError:
    """Tests for BPFNotFoundError."""

    def test_basic_error(self) -> None:
        """Test creating a not found error."""
        err = BPFNotFoundError("program 'foo' not found")
        assert "foo" in str(err)
        assert isinstance(err, BPFError)


class TestBPFPermissionError:
    """Tests for BPFPermissionError."""

    def test_default_message(self) -> None:
        """Test default permission error message."""
        err = BPFPermissionError()
        assert "permission" in str(err).lower()
        assert "CAP_BPF" in str(err) or "root" in str(err)

    def test_custom_message(self) -> None:
        """Test custom permission error message."""
        err = BPFPermissionError("custom error")
        assert str(err) == "custom error"


class TestBPFSyscallError:
    """Tests for BPFSyscallError."""

    def test_with_errno(self) -> None:
        """Test creating a syscall error with errno."""
        err = BPFSyscallError("syscall failed", errno_val=13)  # EACCES
        assert err.errno == 13
        assert "13" in str(err)
        assert err.strerror  # Should have an error string

    def test_inheritance(self) -> None:
        """Test that BPFSyscallError is a BPFError."""
        err = BPFSyscallError("test", 1)
        assert isinstance(err, BPFError)
