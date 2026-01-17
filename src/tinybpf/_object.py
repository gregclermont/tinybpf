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

import ctypes
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tinybpf._libbpf import bindings
from tinybpf._map import BpfMap, MapCollection
from tinybpf._program import BpfProgram, ProgramCollection
from tinybpf._types import (
    BpfError,
    BtfField,
    BtfKind,
    BtfType,
    BtfValidationError,
    _check_ptr,
    btf_kind,
    btf_vlen,
)

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
        self._btf_ptr: Any = None  # Lazy-loaded
        self._type_registry: dict[str, type] = {}  # btf_name -> python_type
        self._reverse_type_registry: dict[type, str] = {}  # python_type -> btf_name

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

    @property
    def btf(self) -> Any | None:
        """Get BTF pointer (lazy-loaded).

        Returns:
            BTF pointer if BTF is available, None otherwise.
        """
        if self._btf_ptr is None:
            lib = bindings._get_lib()
            self._btf_ptr = lib.bpf_object__btf(self._ptr)
        # Check if BTF pointer is NULL (no BTF info)
        if not self._btf_ptr:
            return None
        return self._btf_ptr

    def register_type(
        self,
        btf_name: str,
        python_type: type,
        validate_field_names: bool = True,
    ) -> None:
        """Register a Python type for a BTF struct name.

        This validates the Python type against BTF metadata. The BTF struct
        must exist - registration fails if the struct is not found in BTF.

        The registry enforces a 1:1 mapping: each Python type can only be
        registered to one BTF struct name, and vice versa.

        Note: Event structs used only locally in BPF functions are often
        optimized out of BTF by the compiler. If you get a "not found in BTF"
        error, add a global anchor in your BPF code to preserve the struct::

            struct event _event_btf __attribute__((unused));

        Args:
            btf_name: The BTF struct name (must exist in BTF).
            python_type: The Python ctypes.Structure type.
            validate_field_names: Whether to validate that Python field names
                match BTF field names. Set to False if you want to rename
                fields in your Python type. Defaults to True.

        Raises:
            BpfError: If BTF is not available, the struct is not found in BTF,
                or the type/name is already registered.
            BtfValidationError: If validation finds a size/offset mismatch,
                or field name mismatch (when validate_field_names=True).
        """
        # Check for duplicate registration
        if btf_name in self._type_registry:
            existing_type = self._type_registry[btf_name]
            if existing_type is python_type:
                return  # Already registered with same type - no-op
            raise BpfError(
                f"BTF struct '{btf_name}' is already registered "
                f"with type '{existing_type.__name__}'"
            )
        if python_type in self._reverse_type_registry:
            existing_name = self._reverse_type_registry[python_type]
            raise BpfError(
                f"Type '{python_type.__name__}' is already registered "
                f"as BTF struct '{existing_name}'"
            )

        # Require BTF to be available
        btf = self.btf
        if btf is None:
            raise BpfError(
                f"Cannot register type for BTF struct '{btf_name}': no BTF information available"
            )

        lib = bindings._get_lib()
        type_id = lib.btf__find_by_name_kind(btf, btf_name.encode(), BtfKind.STRUCT)

        if type_id < 0:
            raise BpfError(
                f"BTF struct '{btf_name}' not found in BTF. "
                f"Event structs used only locally in BPF functions are often optimized out. "
                f"To include the struct in BTF, add a global anchor in your BPF code: "
                f"struct {btf_name} _{btf_name}_btf __attribute__((unused));"
            )

        btf_type = self._resolve_btf_type(type_id)
        if btf_type is not None:
            self._validate_python_type(
                python_type, btf_type, validate_field_names=validate_field_names
            )

        self._type_registry[btf_name] = python_type
        self._reverse_type_registry[python_type] = btf_name

    def lookup_type(self, btf_name: str) -> type | None:
        """Look up a registered Python type by BTF struct name.

        Args:
            btf_name: The BTF struct name.

        Returns:
            The registered Python type, or None if not registered.
        """
        return self._type_registry.get(btf_name)

    def lookup_btf_name(self, python_type: type) -> str | None:
        """Look up the registered BTF struct name for a Python type.

        Args:
            python_type: The Python type.

        Returns:
            The registered BTF struct name, or None if not registered.
        """
        return self._reverse_type_registry.get(python_type)

    def _resolve_btf_type(self, type_id: int) -> BtfType | None:
        """Resolve BTF type ID to BtfType, following typedefs.

        Args:
            type_id: The BTF type ID.

        Returns:
            BtfType if found, None if type_id is 0 or BTF unavailable.
        """
        if type_id == 0:
            return None

        btf = self.btf
        if btf is None:
            return None

        lib = bindings._get_lib()

        # Follow typedefs, const, volatile, restrict modifiers
        while True:
            btf_type_ptr = lib.btf__type_by_id(btf, type_id)
            if not btf_type_ptr:
                return None

            info = btf_type_ptr.contents.info
            kind_val = btf_kind(info)

            try:
                kind = BtfKind(kind_val)
            except ValueError:
                kind = BtfKind.UNKN

            # Follow indirections
            if kind in (BtfKind.TYPEDEF, BtfKind.CONST, BtfKind.VOLATILE, BtfKind.RESTRICT):
                type_id = btf_type_ptr.contents.size_or_type
                continue

            # Get type name
            name_off = btf_type_ptr.contents.name_off
            name_bytes = lib.btf__str_by_offset(btf, name_off)
            name = name_bytes.decode("utf-8") if name_bytes else ""

            # Get size (for sized types)
            size: int | None = None
            if kind in (BtfKind.INT, BtfKind.STRUCT, BtfKind.UNION, BtfKind.ENUM, BtfKind.FLOAT):
                size = btf_type_ptr.contents.size_or_type

            # Get fields for struct/union
            fields: tuple[BtfField, ...] | None = None
            if kind in (BtfKind.STRUCT, BtfKind.UNION):
                vlen = btf_vlen(info)
                if vlen > 0:
                    fields = self._get_btf_fields(btf, btf_type_ptr, vlen)

            return BtfType(name=name, kind=kind, size=size, fields=fields)

        return None  # unreachable

    def _get_btf_fields(self, btf: Any, btf_type_ptr: Any, vlen: int) -> tuple[BtfField, ...]:
        """Extract fields from a BTF struct/union type."""
        lib = bindings._get_lib()
        fields = []

        # Members follow immediately after btf_type in memory
        # Each member is 12 bytes (3 x uint32)
        # Use cast to get the actual pointer address (not a copy)
        base_addr = ctypes.cast(btf_type_ptr, ctypes.c_void_p).value
        if base_addr is None:
            return ()
        member_base = base_addr + ctypes.sizeof(bindings._btf_type)

        for i in range(vlen):
            member_addr = member_base + i * ctypes.sizeof(bindings._btf_member)
            member = bindings._btf_member.from_address(member_addr)

            name_bytes = lib.btf__str_by_offset(btf, member.name_off)
            field_name = name_bytes.decode("utf-8") if name_bytes else ""

            # Offset is in bits, convert to bytes
            offset_bytes = member.offset // 8

            # Get field size by resolving its type
            field_type = self._resolve_btf_type(member.type)
            field_size = field_type.size if field_type and field_type.size else 0

            fields.append(BtfField(name=field_name, offset=offset_bytes, size=field_size))

        return tuple(fields)

    def _get_btf_struct_names(self) -> list[str]:
        """Get all struct names in BTF (for error suggestions)."""
        btf = self.btf
        if btf is None:
            return []

        lib = bindings._get_lib()
        type_cnt = lib.btf__type_cnt(btf)
        names = []

        for type_id in range(1, type_cnt):
            btf_type_ptr = lib.btf__type_by_id(btf, type_id)
            if not btf_type_ptr:
                continue

            info = btf_type_ptr.contents.info
            kind_val = btf_kind(info)

            if kind_val == BtfKind.STRUCT:
                name_off = btf_type_ptr.contents.name_off
                name_bytes = lib.btf__str_by_offset(btf, name_off)
                if name_bytes:
                    name = name_bytes.decode("utf-8")
                    if name:  # Skip anonymous structs
                        names.append(name)

        return names

    def _validate_python_type(
        self, python_type: type, btf_type: BtfType, validate_field_names: bool
    ) -> None:
        """Validate Python type against BTF type."""
        # Size check
        if hasattr(python_type, "_fields_") and btf_type.size is not None:
            py_size = ctypes.sizeof(python_type)
            if py_size != btf_type.size:
                raise BtfValidationError(
                    f"Size mismatch: {python_type.__name__} is {py_size} bytes, "
                    f"BTF type '{btf_type.name}' is {btf_type.size} bytes"
                )

        # Field validation for structs
        if btf_type.fields is not None and hasattr(python_type, "_fields_"):
            py_fields = python_type._fields_

            # Field count check
            if len(py_fields) != len(btf_type.fields):
                raise BtfValidationError(
                    f"Field count mismatch: {python_type.__name__} has {len(py_fields)} fields, "
                    f"BTF type '{btf_type.name}' has {len(btf_type.fields)} fields"
                )

            # Per-field validation
            for (py_name, _), btf_field in zip(py_fields, btf_type.fields, strict=True):
                # Offset check
                py_offset = getattr(python_type, py_name).offset
                if py_offset != btf_field.offset:
                    raise BtfValidationError(
                        f"Field '{py_name}' at offset {py_offset}, "
                        f"BTF field '{btf_field.name}' expects offset {btf_field.offset}"
                    )

                # Name check (if enabled)
                if validate_field_names and py_name != btf_field.name:
                    raise BtfValidationError(
                        f"Field name mismatch: Python field '{py_name}', "
                        f"BTF field '{btf_field.name}' at offset {btf_field.offset}"
                    )

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

    # Load the object into the kernel, capturing libbpf's stderr output
    # which contains detailed error info (verifier log, CO-RE errors, etc.)
    with bindings.capture_libbpf_output():
        ret = lib.bpf_object__load(obj_ptr)

    if ret < 0:
        lib.bpf_object__close(obj_ptr)
        err_abs = abs(ret)
        msg = bindings.libbpf_strerror(err_abs)
        libbpf_log = bindings.get_captured_output().strip() or None
        raise BpfError(f"load '{path}' failed: {msg}", errno=err_abs, libbpf_log=libbpf_log)

    return BpfObject(obj_ptr, path)
