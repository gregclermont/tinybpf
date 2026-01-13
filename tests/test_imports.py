"""Tests for package imports."""

import pytest


class TestPackageImports:
    """Test that all public APIs can be imported."""

    def test_import_tinybpf(self) -> None:
        """Test importing the main package."""
        import tinybpf

        assert tinybpf.__version__

    def test_import_load(self) -> None:
        """Test importing the load function."""
        from tinybpf import load

        assert callable(load)

    def test_import_classes(self) -> None:
        """Test importing main classes."""
        from tinybpf import (
            BPFLink,
            BPFMap,
            BPFMapCollection,
            BPFObject,
            BPFProgram,
            MapInfo,
            TypedBPFMap,
        )

        # All should be classes
        assert isinstance(BPFObject, type)
        assert isinstance(BPFProgram, type)
        assert isinstance(BPFMap, type)
        assert isinstance(BPFLink, type)
        assert isinstance(BPFMapCollection, type)
        assert isinstance(TypedBPFMap, type)
        assert isinstance(MapInfo, type)

    def test_import_enums(self) -> None:
        """Test importing enums."""
        from tinybpf import MapType, MapUpdateFlags, ProgramType

        # Test some enum values
        assert MapType.HASH == 1
        assert ProgramType.KPROBE == 2
        assert MapUpdateFlags.ANY == 0

    def test_import_exceptions(self) -> None:
        """Test importing exceptions."""
        from tinybpf import (
            BPFAttachError,
            BPFError,
            BPFLoadError,
            BPFMapError,
            BPFNotFoundError,
            BPFPermissionError,
            BPFSyscallError,
            BPFVerifierError,
        )

        # All should be exception classes
        assert issubclass(BPFError, Exception)
        assert issubclass(BPFLoadError, BPFError)
        assert issubclass(BPFVerifierError, BPFLoadError)
        assert issubclass(BPFAttachError, BPFError)
        assert issubclass(BPFMapError, BPFError)
        assert issubclass(BPFNotFoundError, BPFError)
        assert issubclass(BPFPermissionError, BPFError)
        assert issubclass(BPFSyscallError, BPFError)

    def test_all_exports(self) -> None:
        """Test that __all__ contains expected exports."""
        import tinybpf

        expected = [
            "load",
            "BPFObject",
            "BPFProgram",
            "BPFMap",
            "BPFLink",
            "BPFMapCollection",
            "TypedBPFMap",
            "MapInfo",
            "MapType",
            "MapUpdateFlags",
            "ProgramType",
            "BPFError",
            "BPFLoadError",
            "BPFVerifierError",
            "BPFAttachError",
            "BPFMapError",
            "BPFNotFoundError",
            "BPFPermissionError",
            "BPFSyscallError",
        ]

        for name in expected:
            assert name in tinybpf.__all__, f"{name} not in __all__"
            assert hasattr(tinybpf, name), f"{name} not accessible"


class TestSubmoduleImports:
    """Test importing from submodules."""

    def test_import_enums_module(self) -> None:
        """Test importing from enums module."""
        from tinybpf.enums import MapType, MapUpdateFlags, ProgramType

        assert MapType.HASH.value == 1

    def test_import_exceptions_module(self) -> None:
        """Test importing from exceptions module."""
        from tinybpf.exceptions import BPFError, BPFLoadError

        assert issubclass(BPFLoadError, BPFError)

    def test_import_object_module(self) -> None:
        """Test importing from object module."""
        from tinybpf.object import BPFObject, load

        assert callable(load)

    def test_import_program_module(self) -> None:
        """Test importing from program module."""
        from tinybpf.program import BPFProgram

        assert isinstance(BPFProgram, type)

    def test_import_map_module(self) -> None:
        """Test importing from map module."""
        from tinybpf.map import BPFMap, BPFMapCollection, MapInfo, TypedBPFMap

        assert isinstance(BPFMap, type)

    def test_import_link_module(self) -> None:
        """Test importing from link module."""
        from tinybpf.link import BPFLink

        assert isinstance(BPFLink, type)
