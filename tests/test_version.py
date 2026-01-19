"""Test tinybpf version and initialization."""

import tinybpf


def test_package_version() -> None:
    """Package version is accessible and has valid format."""
    version = tinybpf.version()
    assert version == tinybpf.__version__
    # Verify semver format (X.Y.Z with optional prerelease)
    parts = version.split("-")[0].split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


def test_libbpf_version() -> None:
    """libbpf version is returned (proves .so loads correctly)."""
    version = tinybpf.libbpf_version()
    assert isinstance(version, str)
    assert len(version) > 0
    # Should be something like "1.4.0"
    parts = version.split(".")
    assert len(parts) >= 2
