"""
BPF object management.

This module provides the BPFObject class, which is the main entry point
for loading and working with pre-compiled BPF programs.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from tinybpf._libbpf import get_libbpf
from tinybpf._libbpf.bindings import bpf_object_p, bpf_program_p
from tinybpf.exceptions import BPFLoadError, BPFNotFoundError
from tinybpf.map import BPFMap, BPFMapCollection
from tinybpf.program import BPFProgram


class BPFObject:
    """
    Represents a loaded BPF object file.

    BPFObject is the main entry point for working with pre-compiled
    eBPF programs. It manages the lifecycle of programs, maps, and
    attachments.

    Use the `load()` function or context manager to create instances:

    Example:
        >>> with tinybpf.load("program.bpf.o") as obj:
        ...     # Access programs
        ...     prog = obj.program("trace_connect")
        ...     link = prog.attach_kprobe("tcp_v4_connect")
        ...
        ...     # Access maps
        ...     for key, value in obj.maps["counters"].items():
        ...         print(key.hex(), value.hex())
        ...
        ... # Resources are automatically cleaned up

    Attributes:
        name: The name of the BPF object (typically the filename).
        programs: Iterator over all programs in the object.
        maps: Dict-like collection of maps in the object.
    """

    def __init__(self, path: str | Path) -> None:
        """
        Load a BPF object file.

        This opens the BPF ELF file, parses it, and loads the programs
        and maps into the kernel.

        Args:
            path: Path to the .bpf.o file.

        Raises:
            BPFLoadError: If the file cannot be opened or loaded.
            FileNotFoundError: If the file does not exist.
        """
        self._path = Path(path)
        if not self._path.exists():
            raise FileNotFoundError(f"BPF object file not found: {self._path}")

        self._libbpf = get_libbpf()
        self._ptr: bpf_object_p | None = None
        self._loaded = False
        self._closed = False
        self._programs_cache: dict[str, BPFProgram] = {}
        self._maps: BPFMapCollection | None = None

        # Open and load the object
        self._open_and_load()

    def _open_and_load(self) -> None:
        """Open and load the BPF object."""
        try:
            self._ptr = self._libbpf.object_open(self._path)
        except Exception as e:
            raise BPFLoadError(f"Failed to open BPF object: {self._path}") from e

        try:
            self._libbpf.object_load(self._ptr)
            self._loaded = True
        except Exception as e:
            # Clean up on failure
            if self._ptr:
                self._libbpf.object_close(self._ptr)
                self._ptr = None
            raise BPFLoadError(f"Failed to load BPF object: {self._path}") from e

    @property
    def name(self) -> str:
        """The name of this BPF object."""
        if self._ptr is None:
            return ""
        return self._libbpf.object_name(self._ptr)

    @property
    def path(self) -> Path:
        """The path to the BPF object file."""
        return self._path

    @property
    def is_loaded(self) -> bool:
        """Whether the object is loaded into the kernel."""
        return self._loaded and not self._closed

    @property
    def maps(self) -> BPFMapCollection:
        """
        Dict-like collection of maps in this object.

        Access maps by name:
            >>> counters = obj.maps["counters"]
            >>> for name in obj.maps:
            ...     print(name)
        """
        if self._closed:
            raise RuntimeError("BPF object has been closed")
        if self._maps is None:
            self._maps = BPFMapCollection(self)
        return self._maps

    @property
    def programs(self) -> Iterator[BPFProgram]:
        """
        Iterate over all programs in this object.

        Yields:
            BPFProgram instances for each program.
        """
        if self._closed or self._ptr is None:
            return

        prog_ptr = self._libbpf.next_program(self._ptr, None)
        while prog_ptr:
            name = self._libbpf.program_name(prog_ptr)
            if name not in self._programs_cache:
                self._programs_cache[name] = BPFProgram(prog_ptr, self)
            yield self._programs_cache[name]
            prog_ptr = self._libbpf.next_program(self._ptr, prog_ptr)

    def program(self, name: str) -> BPFProgram:
        """
        Get a program by name.

        Args:
            name: The name of the program (typically the C function name).

        Returns:
            The BPFProgram instance.

        Raises:
            BPFNotFoundError: If no program with that name exists.
        """
        if self._closed or self._ptr is None:
            raise RuntimeError("BPF object has been closed")

        if name in self._programs_cache:
            return self._programs_cache[name]

        try:
            prog_ptr = self._libbpf.find_program_by_name(self._ptr, name)
        except Exception:
            raise BPFNotFoundError(f"Program not found: {name}")

        program = BPFProgram(prog_ptr, self)
        self._programs_cache[name] = program
        return program

    def map(self, name: str) -> BPFMap:
        """
        Get a map by name.

        This is a convenience method equivalent to obj.maps[name].

        Args:
            name: The name of the map.

        Returns:
            The BPFMap instance.

        Raises:
            BPFNotFoundError: If no map with that name exists.
        """
        return self.maps[name]

    def program_names(self) -> list[str]:
        """Get a list of all program names in this object."""
        return [prog.name for prog in self.programs]

    def map_names(self) -> list[str]:
        """Get a list of all map names in this object."""
        return list(self.maps.keys())

    def detach_all(self) -> None:
        """Detach all programs from their hooks."""
        for program in self._programs_cache.values():
            program.detach_all()

    def close(self) -> None:
        """
        Close this object and release all resources.

        This detaches all programs and frees kernel resources.
        After calling close(), the object can no longer be used.
        """
        if self._closed:
            return

        # Detach all programs first
        self.detach_all()

        # Close the object
        if self._ptr:
            self._libbpf.object_close(self._ptr)
            self._ptr = None

        self._closed = True
        self._loaded = False
        self._programs_cache.clear()
        self._maps = None

    def __enter__(self) -> BPFObject:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Context manager exit - closes the object."""
        self.close()

    def __del__(self) -> None:
        """Destructor - ensures resources are cleaned up."""
        if not self._closed:
            try:
                self.close()
            except Exception:
                pass  # Ignore errors during cleanup

    def __repr__(self) -> str:
        status = "loaded" if self.is_loaded else "closed"
        return f"BPFObject({self._path.name!r}, {status})"


def load(path: str | Path) -> BPFObject:
    """
    Load a pre-compiled BPF object file.

    This is the main entry point for loading eBPF programs.

    Args:
        path: Path to the .bpf.o file compiled with clang.

    Returns:
        A BPFObject instance that can be used to access programs and maps.

    Raises:
        BPFLoadError: If the file cannot be loaded.
        FileNotFoundError: If the file does not exist.

    Example:
        >>> with tinybpf.load("trace.bpf.o") as obj:
        ...     prog = obj.program("trace_exec")
        ...     link = prog.attach_tracepoint("syscalls", "sys_enter_execve")
        ...     # Do work while tracing...
    """
    return BPFObject(path)
