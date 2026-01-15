"""High-level eBPF object loading and manipulation.

This module provides the main entry point for loading pre-compiled CO-RE
eBPF programs. Use the load() function to create BpfObject instances.

Example:
    with tinybpf.load("program.bpf.o") as obj:
        obj.program("trace_connect").attach_kprobe("tcp_v4_connect")
        for key, value in obj.maps["connections"].items():
            ...
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from tinybpf._libbpf import bindings
from tinybpf._map import BpfMap, MapCollection
from tinybpf._program import BpfProgram, ProgramCollection
from tinybpf._types import _check_err, _check_ptr

if TYPE_CHECKING:
    from types import TracebackType


class BpfObject:
    """A loaded BPF object file.

    Use the `load()` function to create instances. BpfObject supports
    the context manager protocol for automatic resource cleanup.

    Example:
        with tinybpf.load("program.bpf.o") as obj:
            print(obj.name)
            for prog in obj.programs.values():
                print(prog.name, prog.type)
    """

    def __init__(self, obj_ptr: Any, path: Path) -> None:
        self._ptr = obj_ptr
        self._path = path
        self._closed = False

        lib = bindings._get_lib()
        name = lib.bpf_object__name(obj_ptr)
        self._name = name.decode("utf-8") if name else path.stem

        # Collect programs
        self._programs: dict[str, BpfProgram] = {}
        prog = lib.bpf_object__next_program(obj_ptr, None)
        while prog:
            bp = BpfProgram(prog, self)
            self._programs[bp.name] = bp
            prog = lib.bpf_object__next_program(obj_ptr, prog)

        # Collect maps
        self._maps: dict[str, BpfMap[Any, Any]] = {}
        map_ = lib.bpf_object__next_map(obj_ptr, None)
        while map_:
            bm: BpfMap[Any, Any] = BpfMap(map_, self)
            self._maps[bm.name] = bm
            map_ = lib.bpf_object__next_map(obj_ptr, map_)

    def __enter__(self) -> BpfObject:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            self.close()

    def __repr__(self) -> str:
        status = "closed" if self._closed else "open"
        return f"<BpfObject '{self._name}' {status} programs={len(self._programs)} maps={len(self._maps)}>"

    @property
    def name(self) -> str:
        """Return the object name."""
        return self._name

    @property
    def path(self) -> Path:
        """Return the path to the object file."""
        return self._path

    @property
    def programs(self) -> ProgramCollection:
        """Return collection of programs in this object."""
        return ProgramCollection(self._programs)

    @property
    def maps(self) -> MapCollection:
        """Return collection of maps in this object."""
        return MapCollection(self._maps)

    def program(self, name: str) -> BpfProgram:
        """Get a program by name.

        Args:
            name: The program name.

        Returns:
            The BpfProgram instance.

        Raises:
            KeyError: If program not found.
        """
        return self._programs[name]

    def map(self, name: str) -> BpfMap[Any, Any]:
        """Get a map by name.

        Args:
            name: The map name.

        Returns:
            The BpfMap instance.

        Raises:
            KeyError: If map not found.
        """
        return self._maps[name]

    def close(self) -> None:
        """Close and release the BPF object resources."""
        if self._closed:
            return
        lib = bindings._get_lib()
        lib.bpf_object__close(self._ptr)
        self._closed = True


def load(path: str | Path) -> BpfObject:
    """Load a BPF object file.

    This opens and loads a pre-compiled CO-RE eBPF object file (.bpf.o).
    The returned object can be used with a context manager for automatic cleanup.

    Args:
        path: Path to the .bpf.o file.

    Returns:
        A BpfObject instance with programs and maps ready to use.

    Raises:
        BpfError: If loading fails.
        FileNotFoundError: If the file doesn't exist.

    Example:
        with tinybpf.load("program.bpf.o") as obj:
            link = obj.program("trace_openat").attach()
            # ... do work ...
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"BPF object file not found: {path}")

    lib = bindings._get_lib()

    # Open the object file
    obj_ptr = lib.bpf_object__open_file(str(path).encode("utf-8"), None)
    _check_ptr(obj_ptr, f"open '{path}'")

    # Load the object into the kernel
    ret = lib.bpf_object__load(obj_ptr)
    if ret < 0:
        lib.bpf_object__close(obj_ptr)
        _check_err(ret, f"load '{path}'")

    return BpfObject(obj_ptr, path)
