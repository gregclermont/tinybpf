"""Test tinybpf version and initialization."""

import tinybpf


def test_package_version() -> None:
    """Package version is accessible."""
    assert tinybpf.version() == "0.0.1"
    assert tinybpf.__version__ == "0.0.1"


def test_libbpf_version() -> None:
    """libbpf version is returned (proves .so loads correctly)."""
    version = tinybpf.libbpf_version()
    assert isinstance(version, str)
    assert len(version) > 0
    # Should be something like "1.4.0"
    parts = version.split(".")
    assert len(parts) >= 2
