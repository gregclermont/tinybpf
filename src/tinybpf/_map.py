"""BPF map access and manipulation.

This module provides dict-like access to BPF maps with support for
various key/value types including bytes, integers, and ctypes structures.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import struct
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any, Generic, TypeVar, overload

from tinybpf._libbpf import bindings
from tinybpf._types import (
    BPF_ANY,
    BpfError,
    BpfMapType,
    BtfKind,
    BtfType,
    BtfValidationError,
    MapInfo,
    _BpfMapInfoKernel,
    _check_err,
)

if TYPE_CHECKING:
    import builtins
    from types import TracebackType

    from tinybpf._object import BpfObject

KT = TypeVar("KT")
VT = TypeVar("VT")
# Method-level TypeVars for typed(), so the returned view's element types
# reflect the key=/value= arguments rather than the source map's TypeVars.
KT2 = TypeVar("KT2")
VT2 = TypeVar("VT2")

# BTF INT encoding flags. The encoding __u32 immediately follows btf_type in
# memory for KIND_INT types. BTF_INT_ENCODING(VAL) = (VAL & 0x0f000000) >> 24.
_BTF_INT_SIGNED = 0x1

# Sentinel marking a BTF cache slot as not-yet-resolved (distinct from None,
# which is a valid resolved result meaning "no BTF available").
_UNRESOLVED = object()

# Per-CPU map types that require special handling
_PERCPU_MAP_TYPES = frozenset(
    {
        BpfMapType.PERCPU_HASH,
        BpfMapType.PERCPU_ARRAY,
        BpfMapType.LRU_PERCPU_HASH,
        BpfMapType.PERCPU_CGROUP_STORAGE,
    }
)


class BpfMap(Generic[KT, VT]):
    """A BPF map.

    Maps can be obtained in two ways:

    **Object-owned maps** (typical usage):
        Obtained from BpfObject.maps or BpfObject.map(). Lifecycle is tied
        to the parent BpfObject. Support pin() and unpin().

    **Standalone maps** (from pinned path):
        Obtained from open_pinned_map(). Own their file descriptor and
        must be closed explicitly or via context manager. Do not support
        pin() or unpin().

    Provides dict-like access to map elements and iteration support.
    By default, keys and values are treated as raw bytes.
    """

    def __init__(
        self,
        map_ptr: Any = None,
        obj: BpfObject | None = None,
        *,
        # For standalone maps (from open_pinned_map)
        owned_fd: int | None = None,
        name: str | None = None,
        map_type: BpfMapType | None = None,
        key_size: int | None = None,
        value_size: int | None = None,
        max_entries: int | None = None,
        # Type hints for key/value conversion
        key_type: type[KT] | None = None,
        value_type: type[VT] | None = None,
    ) -> None:
        self._ptr = map_ptr
        self._obj = obj  # Keep reference to prevent GC (object-owned maps)
        self._owned_fd = owned_fd  # fd we own (standalone maps)
        self._closed = False
        self._key_type = key_type
        self._value_type = value_type

        # Lazily-resolved BTF info, cached so per-element conversions during
        # iteration don't re-run the full BTF resolution walk on every call.
        # Sentinel _UNRESOLVED distinguishes "not yet computed" from "no BTF".
        self._btf_key_cache: BtfType | None | object = _UNRESOLVED
        self._btf_value_cache: BtfType | None | object = _UNRESOLVED
        self._btf_key_signed: bool | None = None
        self._btf_value_signed: bool | None = None

        if map_ptr is not None:
            # Object-owned map: extract info from libbpf pointer
            lib = bindings._get_lib()
            self._name = lib.bpf_map__name(map_ptr).decode("utf-8")
            self._type = BpfMapType(lib.bpf_map__type(map_ptr))
            self._key_size = lib.bpf_map__key_size(map_ptr)
            self._value_size = lib.bpf_map__value_size(map_ptr)
            self._max_entries = lib.bpf_map__max_entries(map_ptr)
        else:
            # Standalone map: use provided values
            self._name = name or ""
            self._type = map_type or BpfMapType.UNSPEC
            self._key_size = key_size or 0
            self._value_size = value_size or 0
            self._max_entries = max_entries or 0

    def __repr__(self) -> str:
        return (
            f"<BpfMap '{self._name}' type={self._type.name} "
            f"key_size={self._key_size} value_size={self._value_size}>"
        )

    @property
    def name(self) -> str:
        """Return the map name."""
        return self._name

    @property
    def type(self) -> BpfMapType:
        """Return the map type."""
        return self._type

    @property
    def key_size(self) -> int:
        """Return the key size in bytes."""
        return self._key_size

    @property
    def value_size(self) -> int:
        """Return the value size in bytes."""
        return self._value_size

    @property
    def max_entries(self) -> int:
        """Return the maximum number of entries."""
        return self._max_entries

    @property
    def fd(self) -> int:
        """Return the map file descriptor."""
        self._check_open()
        if self._owned_fd is not None:
            return self._owned_fd
        lib = bindings._get_lib()
        return lib.bpf_map__fd(self._ptr)

    @property
    def info(self) -> MapInfo:
        """Return map information as a dataclass."""
        return MapInfo(
            name=self._name,
            type=self._type,
            key_size=self._key_size,
            value_size=self._value_size,
            max_entries=self._max_entries,
        )

    @property
    def is_standalone(self) -> bool:
        """Return True if this map was opened from a pinned path."""
        return self._owned_fd is not None

    @property
    def is_percpu(self) -> bool:
        """Return True if this map is a per-CPU map type."""
        return self._type in _PERCPU_MAP_TYPES

    @property
    def btf_key(self) -> BtfType | None:
        """Return BTF type info for map key, or None if no BTF.

        The resolved type is cached on the instance after first access, so
        repeated conversions during iteration do not re-walk BTF metadata.

        Returns:
            BtfType describing the key type, or None if BTF is unavailable.
        """
        if self._btf_key_cache is _UNRESOLVED:
            self._btf_key_cache, self._btf_key_signed = self._resolve_btf(
                lambda lib: lib.bpf_map__btf_key_type_id(self._ptr)
            )
        return self._btf_key_cache  # type: ignore[return-value]

    @property
    def btf_value(self) -> BtfType | None:
        """Return BTF type info for map value, or None if no BTF.

        The resolved type is cached on the instance after first access, so
        repeated conversions during iteration do not re-walk BTF metadata.

        Returns:
            BtfType describing the value type, or None if BTF is unavailable.
        """
        if self._btf_value_cache is _UNRESOLVED:
            self._btf_value_cache, self._btf_value_signed = self._resolve_btf(
                lambda lib: lib.bpf_map__btf_value_type_id(self._ptr)
            )
        return self._btf_value_cache  # type: ignore[return-value]

    def _resolve_btf(self, type_id_fn: Any) -> tuple[BtfType | None, bool | None]:
        """Resolve a map BTF type and its INT signedness (uncached).

        Args:
            type_id_fn: Callable taking the libbpf handle and returning the
                BTF type id for the key or value.

        Returns:
            A (BtfType | None, signed | None) tuple. ``signed`` is True/False
            for INT kinds and None when signedness is not applicable/unknown.
        """
        if self._obj is None or self._obj.btf is None or self._ptr is None:
            return None, None
        lib = bindings._get_lib()
        type_id = type_id_fn(lib)
        if type_id == 0:
            return None, None
        btf_type = self._obj._resolve_btf_type(type_id)
        signed: bool | None = None
        if btf_type is not None and btf_type.kind == BtfKind.INT:
            signed = self._btf_int_signed(type_id)
        return btf_type, signed

    def _btf_int_signed(self, type_id: int) -> bool | None:
        """Return whether the BTF INT type at type_id is signed.

        The BTF INT encoding is a __u32 stored immediately after the
        btf_type struct in memory. The signedness lives in the encoding's
        high byte (BTF_INT_ENCODING). Returns None if it cannot be read.
        """
        if self._obj is None or self._obj.btf is None:
            return None
        lib = bindings._get_lib()
        btf_type_ptr = lib.btf__type_by_id(self._obj.btf, type_id)
        if not btf_type_ptr:
            return None
        base_addr = ctypes.cast(btf_type_ptr, ctypes.c_void_p).value
        if base_addr is None:
            return None
        encoding = ctypes.c_uint32.from_address(base_addr + ctypes.sizeof(bindings._btf_type)).value
        return bool(((encoding & 0x0F000000) >> 24) & _BTF_INT_SIGNED)

    @overload
    def typed(
        self,
        *,
        key: builtins.type[KT2],
        value: builtins.type[VT2],
        validate_field_names: bool = ...,
    ) -> BpfMap[KT2, VT2]: ...

    @overload
    def typed(
        self,
        *,
        key: builtins.type[KT2],
        value: None = ...,
        validate_field_names: bool = ...,
    ) -> BpfMap[KT2, Any]: ...

    @overload
    def typed(
        self,
        *,
        key: None = ...,
        value: builtins.type[VT2],
        validate_field_names: bool = ...,
    ) -> BpfMap[Any, VT2]: ...

    @overload
    def typed(
        self,
        *,
        key: None = ...,
        value: None = ...,
        validate_field_names: bool = ...,
    ) -> BpfMap[Any, Any]: ...

    def typed(
        self,
        *,
        key: builtins.type[KT2] | None = None,
        value: builtins.type[VT2] | None = None,
        validate_field_names: bool = True,
    ) -> BpfMap[Any, Any]:
        """Return a new typed view of this map with BTF validation.

        Creates a typed view that auto-converts keys and values during
        read operations. If BTF metadata is available, validates the
        Python types against it.

        Args:
            key: Type for keys (int or ctypes.Structure subclass).
            value: Type for values (int or ctypes.Structure subclass).
            validate_field_names: If True, validate field names match BTF.
                If False, only validate sizes and offsets.

        Returns:
            A new BpfMap instance with type conversion enabled.

        Raises:
            BtfValidationError: If Python type doesn't match BTF metadata.

        Example:
            # Get typed map view with validation
            counters = obj.maps["counters"].typed(key=int, value=int)
            counters[0] = 42
            assert isinstance(counters[0], int)

            # Typed struct access
            class Event(ctypes.Structure):
                _fields_ = [("pid", c_uint32), ("comm", c_char * 16)]

            events = obj.maps["events"].typed(value=Event)
        """
        if value is not None:
            self._validate_type(value, self.btf_value, validate_field_names)
        if key is not None:
            self._validate_type(key, self.btf_key, validate_field_names)

        # For standalone maps the view must own its own fd. Sharing the same
        # int across two instances (each with its own _closed flag) would let
        # both close() / __del__ call os.close on it - a double-close that can
        # later hit an unrelated reused fd. os.dup() gives the view a genuinely
        # independent fd, so each instance owns and closes exactly one.
        view_owned_fd: int | None = None
        if self._owned_fd is not None:
            self._check_open()
            view_owned_fd = os.dup(self._owned_fd)

        return BpfMap(
            self._ptr,
            self._obj,
            owned_fd=view_owned_fd,
            name=self._name,
            map_type=self._type,
            key_size=self._key_size,
            value_size=self._value_size,
            max_entries=self._max_entries,
            key_type=key,
            value_type=value,
        )

    def _validate_type(
        self,
        python_type: builtins.type,
        btf_type: BtfType | None,
        validate_field_names: bool,
    ) -> None:
        """Validate Python type against BTF type.

        Args:
            python_type: The Python type to validate.
            btf_type: The BTF type to validate against (None if no BTF).
            validate_field_names: Whether to validate field names.

        Raises:
            BtfValidationError: If validation fails.
        """
        # Size check (always, for ctypes structures)
        if hasattr(python_type, "_fields_"):
            py_size = ctypes.sizeof(python_type)
            if btf_type is not None and btf_type.size is not None and py_size != btf_type.size:
                raise BtfValidationError(
                    f"Size mismatch: {python_type.__name__} is {py_size} bytes, "
                    f"BTF type '{btf_type.name}' is {btf_type.size} bytes"
                )

        if btf_type is None:
            return  # No BTF, skip further validation

        # Delegate to object's validation if available
        if self._obj is not None:
            self._obj._validate_python_type(python_type, btf_type, validate_field_names)

    def _check_open(self) -> None:
        """Raise if map is not usable."""
        if self._closed:
            raise BpfError("Map is closed")
        if self._obj is not None and self._obj._closed:
            raise BpfError("Cannot use map after BpfObject is closed")

    def _int_to_bytes(self, value: int, size: int, signed: bool | None, what: str) -> bytes:
        """Convert a Python int to little-endian bytes, honoring signedness.

        Args:
            value: The integer to encode.
            size: Target width in bytes.
            signed: True/False per the BTF INT type, or None when unknown.
            what: "key" or "value", used in error messages.

        A negative value is only accepted when the underlying type is signed
        (or unknown, where we permit it by falling back to signed encoding).
        For a known-unsigned type a negative value raises a clear ValueError.
        """
        if value < 0:
            if signed is False:
                raise ValueError(
                    f"Cannot encode negative {what} {value} for unsigned BTF type of '{self._name}'"
                )
            use_signed = True
        else:
            use_signed = bool(signed)
        try:
            return value.to_bytes(size, byteorder="little", signed=use_signed)
        except OverflowError as exc:
            raise ValueError(
                f"{what.capitalize()} {value} does not fit in {size} bytes for '{self._name}'"
            ) from exc

    def _to_key_bytes(self, key: KT) -> bytes:
        """Convert key to bytes."""
        if isinstance(key, bytes):
            if len(key) != self._key_size:
                raise ValueError(f"Key size mismatch: got {len(key)}, expected {self._key_size}")
            return key
        if isinstance(key, ctypes.Structure | ctypes._SimpleCData):
            return bytes(key)
        if isinstance(key, int):
            signed = self._btf_int_signedness(self._key_type, is_key=True)
            return self._int_to_bytes(key, self._key_size, signed, "key")
        raise TypeError(f"Cannot convert {type(key).__name__} to key bytes")

    def _to_value_bytes(self, value: VT) -> bytes:
        """Convert value to bytes."""
        if isinstance(value, bytes):
            if len(value) != self._value_size:
                raise ValueError(
                    f"Value size mismatch: got {len(value)}, expected {self._value_size}"
                )
            return value
        if isinstance(value, ctypes.Structure | ctypes._SimpleCData):
            return bytes(value)
        if isinstance(value, int):
            signed = self._btf_int_signedness(self._value_type, is_key=False)
            return self._int_to_bytes(value, self._value_size, signed, "value")
        raise TypeError(f"Cannot convert {type(value).__name__} to value bytes")

    def _btf_int_signedness(
        self, explicit_type: builtins.type | None, *, is_key: bool
    ) -> bool | None:
        """Return signedness for a plain-int key/value, or None if unknown.

        Only relevant when no explicit ctypes type is given (plain ``int``):
        ctypes simple types like c_int32 carry their own signedness and are
        handled by ctypes directly. Triggers BTF resolution (cached) to learn
        whether the map's INT type is signed.
        """
        if explicit_type is not None and explicit_type is not int:
            return None
        # Accessing the property populates the cached signedness fields.
        _ = self.btf_key if is_key else self.btf_value
        return self._btf_key_signed if is_key else self._btf_value_signed

    def _from_key_bytes(self, data: bytes) -> KT:
        """Convert bytes to key type."""
        if self._key_type is not None:
            # Explicit type provided - use it
            if self._key_type is int:
                signed = bool(self._btf_int_signedness(self._key_type, is_key=True))
                return int.from_bytes(data, byteorder="little", signed=signed)  # type: ignore
            if issubclass(self._key_type, ctypes.Structure):
                return self._key_type.from_buffer_copy(data)
            if issubclass(self._key_type, ctypes._SimpleCData):
                # ctypes simple types (c_int32, c_uint64, ...) carry their own
                # signedness; return the unwrapped Python scalar.
                return self._key_type.from_buffer_copy(data).value
            raise TypeError(
                f"typed() key must be int or ctypes type, not {self._key_type.__name__}. "
                f"Use int for scalar types."
            )

        # No explicit type - check BTF for auto-inference
        btf_type = self.btf_key
        if btf_type is not None:
            if btf_type.kind == BtfKind.INT:
                signed = bool(self._btf_key_signed)
                return int.from_bytes(data, byteorder="little", signed=signed)  # type: ignore
            if btf_type.kind == BtfKind.FLOAT:
                fmt = "f" if len(data) == 4 else "d"
                return struct.unpack(fmt, data)[0]

        # Fallback: return bytes
        return data  # type: ignore

    def _from_value_bytes(self, data: bytes) -> VT:
        """Convert bytes to value type."""
        if self._value_type is not None:
            # Explicit type provided - use it
            if self._value_type is int:
                signed = bool(self._btf_int_signedness(self._value_type, is_key=False))
                return int.from_bytes(data, byteorder="little", signed=signed)  # type: ignore
            if issubclass(self._value_type, ctypes.Structure):
                return self._value_type.from_buffer_copy(data)
            if issubclass(self._value_type, ctypes._SimpleCData):
                # ctypes simple types carry their own signedness.
                return self._value_type.from_buffer_copy(data).value
            raise TypeError(
                f"typed() value must be int or ctypes type, not {self._value_type.__name__}. "
                f"Use int for scalar types."
            )

        # No explicit type - check BTF for auto-inference
        btf_type = self.btf_value
        if btf_type is not None:
            if btf_type.kind == BtfKind.INT:
                signed = bool(self._btf_value_signed)
                return int.from_bytes(data, byteorder="little", signed=signed)  # type: ignore
            if btf_type.kind == BtfKind.FLOAT:
                fmt = "f" if len(data) == 4 else "d"
                return struct.unpack(fmt, data)[0]

        # Fallback: return bytes
        return data  # type: ignore

    def _percpu_value_stride(self) -> int:
        """Return the stride between per-CPU values (8-byte aligned)."""
        return (self._value_size + 7) & ~7

    def lookup(self, key: KT) -> VT | None:
        """Look up a value by key.

        Args:
            key: The key to look up (bytes, int, or ctypes.Structure).

        Returns:
            The value if found, None otherwise.

        Raises:
            TypeError: If called on a per-CPU map (use lookup_percpu instead).
        """
        if self.is_percpu:
            raise TypeError(
                f"lookup() is not supported for per-CPU maps. "
                f"Use lookup_percpu() or lookup_percpu_sum() for '{self._name}'"
            )
        self._check_open()
        lib = bindings._get_lib()
        key_bytes = self._to_key_bytes(key)
        key_buf = ctypes.create_string_buffer(key_bytes, self._key_size)
        value_buf = ctypes.create_string_buffer(self._value_size)

        ret = lib.bpf_map_lookup_elem(
            self.fd, ctypes.cast(key_buf, ctypes.c_void_p), ctypes.cast(value_buf, ctypes.c_void_p)
        )
        if ret < 0:
            err = abs(ret)
            if err == errno.ENOENT:
                return None  # Key not found - expected, dict-like behavior
            msg = bindings.libbpf_strerror(err)
            raise BpfError(f"Map lookup failed for '{self._name}': {msg}", errno=err)
        return self._from_value_bytes(value_buf.raw)

    def lookup_percpu(self, key: KT) -> list[VT] | None:
        """Look up per-CPU values by key.

        For per-CPU maps, returns a list of values, one per possible CPU.
        The list is indexed by CPU number.

        Args:
            key: The key to look up (bytes, int, or ctypes.Structure).

        Returns:
            List of values indexed by CPU, or None if key not found.

        Raises:
            TypeError: If called on a non-per-CPU map.
        """
        if not self.is_percpu:
            raise TypeError(
                f"lookup_percpu() is only valid for per-CPU maps, "
                f"but '{self._name}' is {self._type.name}"
            )
        self._check_open()
        lib = bindings._get_lib()

        num_cpus = bindings.num_possible_cpus()
        _check_err(num_cpus, "get number of possible CPUs")
        stride = self._percpu_value_stride()

        key_bytes = self._to_key_bytes(key)
        key_buf = ctypes.create_string_buffer(key_bytes, self._key_size)
        value_buf = ctypes.create_string_buffer(num_cpus * stride)

        ret = lib.bpf_map_lookup_elem(
            self.fd, ctypes.cast(key_buf, ctypes.c_void_p), ctypes.cast(value_buf, ctypes.c_void_p)
        )
        if ret < 0:
            err = abs(ret)
            if err == errno.ENOENT:
                return None  # Key not found
            msg = bindings.libbpf_strerror(err)
            raise BpfError(f"Map lookup failed for '{self._name}': {msg}", errno=err)

        # Extract per-CPU values
        result: list[VT] = []
        for cpu in range(num_cpus):
            offset = cpu * stride
            cpu_data = value_buf.raw[offset : offset + self._value_size]
            result.append(self._from_value_bytes(cpu_data))
        return result

    def lookup_percpu_sum(self, key: KT) -> int | float | None:
        """Look up per-CPU values and return their sum.

        Convenience method for summing counters across all CPUs.
        Only works with numeric value types (int or float).

        Args:
            key: The key to look up.

        Returns:
            Sum of values across all CPUs, or None if key not found.

        Raises:
            TypeError: If called on a non-per-CPU map or value type is not numeric.
        """
        values = self.lookup_percpu(key)
        if values is None:
            return None

        # Check that values are numeric
        if not values:
            return 0

        first = values[0]
        if not isinstance(first, int | float):
            raise TypeError(
                f"lookup_percpu_sum() requires numeric values, but got {type(first).__name__}"
            )

        return sum(values)  # type: ignore[arg-type]

    def items_percpu(self) -> Iterator[tuple[KT, list[VT]]]:
        """Iterate over (key, per-CPU values) pairs.

        Yields:
            Tuples of (key, list of values per CPU).

        Raises:
            TypeError: If called on a non-per-CPU map.
        """
        if not self.is_percpu:
            raise TypeError(
                f"items_percpu() is only valid for per-CPU maps, "
                f"but '{self._name}' is {self._type.name}"
            )
        for key in self.keys():
            values = self.lookup_percpu(key)
            if values is not None:
                yield key, values

    def update(self, key: KT, value: VT, flags: int = BPF_ANY) -> None:
        """Update a map element.

        Args:
            key: The key to update.
            value: The new value.
            flags: Update flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST).

        Raises:
            BpfError: If update fails.
            TypeError: If called on a per-CPU map.
        """
        if self.is_percpu:
            raise TypeError(
                f"update() is not supported for per-CPU maps. "
                f"Per-CPU values can only be written from BPF programs for '{self._name}'"
            )
        self._check_open()
        lib = bindings._get_lib()
        key_bytes = self._to_key_bytes(key)
        value_bytes = self._to_value_bytes(value)
        key_buf = ctypes.create_string_buffer(key_bytes, self._key_size)
        value_buf = ctypes.create_string_buffer(value_bytes, self._value_size)

        ret = lib.bpf_map_update_elem(
            self.fd,
            ctypes.cast(key_buf, ctypes.c_void_p),
            ctypes.cast(value_buf, ctypes.c_void_p),
            flags,
        )
        _check_err(ret, f"update map '{self._name}'")

    def delete(self, key: KT) -> bool:
        """Delete a map element.

        Args:
            key: The key to delete.

        Returns:
            True if element was deleted, False if not found.
        """
        self._check_open()
        lib = bindings._get_lib()
        key_bytes = self._to_key_bytes(key)
        key_buf = ctypes.create_string_buffer(key_bytes, self._key_size)

        ret = lib.bpf_map_delete_elem(self.fd, ctypes.cast(key_buf, ctypes.c_void_p))
        if ret < 0:
            err = abs(ret)
            if err == errno.ENOENT:
                return False  # Key not found
            msg = bindings.libbpf_strerror(err)
            raise BpfError(f"Map delete failed for '{self._name}': {msg}", errno=err)
        return True

    def __getitem__(self, key: KT) -> VT:
        """Get a value by key, raising KeyError if not found."""
        value = self.lookup(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: KT, value: VT) -> None:
        """Set a value by key."""
        self.update(key, value)

    def __delitem__(self, key: KT) -> None:
        """Delete a value by key, raising KeyError if not found."""
        if not self.delete(key):
            raise KeyError(key)

    def __contains__(self, key: KT) -> bool:
        """Check if key exists in map."""
        return self.lookup(key) is not None

    def __iter__(self) -> Iterator[KT]:
        """Iterate over map keys."""
        return self.keys()

    def keys(self) -> Iterator[KT]:
        """Iterate over map keys.

        Yields:
            Each key in the map.
        """
        self._check_open()
        lib = bindings._get_lib()
        prev_key: bytes | None = None
        next_key_buf = ctypes.create_string_buffer(self._key_size)

        while True:
            if prev_key is None:
                prev_key_ptr = None
            else:
                prev_key_buf = ctypes.create_string_buffer(prev_key, self._key_size)
                prev_key_ptr = ctypes.cast(prev_key_buf, ctypes.c_void_p)

            ret = lib.bpf_map_get_next_key(
                self.fd, prev_key_ptr, ctypes.cast(next_key_buf, ctypes.c_void_p)
            )
            if ret < 0:
                err = abs(ret)
                if err == errno.ENOENT:
                    break  # No more keys - normal termination
                msg = bindings.libbpf_strerror(err)
                raise BpfError(f"Map iteration failed for '{self._name}': {msg}", errno=err)

            key_bytes = next_key_buf.raw
            yield self._from_key_bytes(key_bytes)
            prev_key = key_bytes

    def values(self) -> Iterator[VT]:
        """Iterate over map values.

        Yields:
            Each value in the map.
        """
        for key in self.keys():
            value = self.lookup(key)
            if value is not None:
                yield value

    def items(self) -> Iterator[tuple[KT, VT]]:
        """Iterate over (key, value) pairs.

        Yields:
            Tuples of (key, value) for each entry.
        """
        for key in self.keys():
            value = self.lookup(key)
            if value is not None:
                yield key, value

    def get(self, key: KT, default: VT | None = None) -> VT | None:
        """Get a value with a default if not found."""
        value = self.lookup(key)
        return value if value is not None else default

    def pin(self, path: str) -> None:
        """Pin this map to the BPF filesystem.

        The map will persist at the given path until unpinned or the
        system reboots. Other processes can open the pinned map using
        open_pinned_map().

        Args:
            path: Path in bpffs (e.g., "/sys/fs/bpf/my_map").

        Raises:
            BpfError: If pinning fails or map is standalone.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("Cannot pin a standalone map")
        lib = bindings._get_lib()
        ret = lib.bpf_map__pin(self._ptr, path.encode("utf-8"))
        _check_err(ret, f"pin map '{self._name}' to '{path}'")

    def unpin(self, path: str) -> None:
        """Unpin this map from the BPF filesystem.

        Args:
            path: Path where map was pinned.

        Raises:
            BpfError: If unpinning fails or map is standalone.
        """
        self._check_open()
        if self._ptr is None:
            raise BpfError("Cannot unpin a standalone map")
        lib = bindings._get_lib()
        ret = lib.bpf_map__unpin(self._ptr, path.encode("utf-8"))
        _check_err(ret, f"unpin map '{self._name}' from '{path}'")

    def close(self) -> None:
        """Close a standalone map, releasing its file descriptor.

        Only applicable to maps obtained from open_pinned_map().
        Object-owned maps are closed when their parent BpfObject is closed.
        """
        if self._owned_fd is not None and not self._closed:
            os.close(self._owned_fd)
        self._closed = True

    def __enter__(self) -> BpfMap[KT, VT]:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: builtins.type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit - closes standalone maps."""
        self.close()

    def __del__(self) -> None:
        """Clean up file descriptor on garbage collection."""
        if self._owned_fd is not None and not self._closed:
            with contextlib.suppress(OSError):
                os.close(self._owned_fd)


class MapCollection(Mapping[str, BpfMap[Any, Any]]):
    """Collection of BPF maps in an object, accessible by name."""

    def __init__(self, maps: dict[str, BpfMap[Any, Any]]) -> None:
        self._maps = maps

    def __getitem__(self, name: str) -> BpfMap[Any, Any]:
        return self._maps[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._maps)

    def __len__(self) -> int:
        return len(self._maps)

    def __repr__(self) -> str:
        return f"<MapCollection {list(self._maps.keys())}>"


def open_pinned_map(
    path: str,
    key_type: type[KT] | None = None,
    value_type: type[VT] | None = None,
) -> BpfMap[KT, VT]:
    """Open a pinned BPF map by path.

    Opens a map that was previously pinned to the BPF filesystem using
    BpfMap.pin(). The returned map can be used for reading and writing
    data, and must be closed when done.

    Args:
        path: Path to pinned map (e.g., "/sys/fs/bpf/my_map").
        key_type: Optional type for key conversion (int or ctypes.Structure).
        value_type: Optional type for value conversion (int or ctypes.Structure).

    Returns:
        A standalone BpfMap that must be closed when done.

    Raises:
        BpfError: If opening the pinned map fails.

    Example:
        with open_pinned_map("/sys/fs/bpf/my_events") as events:
            for key, value in events.items():
                print(key, value)
    """
    lib = bindings._get_lib()

    # Open the pinned object - returns fd or negative errno. bpf_obj_get works
    # for any pinned object (map, prog, link), so the fd is not guaranteed to
    # be a map yet.
    fd = lib.bpf_obj_get(path.encode("utf-8"))
    if fd < 0:
        _check_err(fd, f"open pinned map '{path}'")

    # Get map info via bpf_obj_get_info_by_fd
    info = _BpfMapInfoKernel()
    info_len = ctypes.c_uint32(ctypes.sizeof(info))

    ret = lib.bpf_obj_get_info_by_fd(
        fd,
        ctypes.byref(info),
        ctypes.byref(info_len),
    )
    if ret < 0:
        os.close(fd)
        _check_err(ret, f"get info for pinned map '{path}'")

    # Verify the fd really is a map before trusting the parsed info (the same
    # call works for pinned progs/links, whose info would be misread through
    # _BpfMapInfoKernel as garbage). A map-only syscall (get_next_key with no
    # previous key) returns 0 or -ENOENT (empty map) for a real map, but fails
    # cleanly (e.g. -EINVAL) on a prog/link fd. The kernel rejects a non-map fd
    # before touching the key buffer, so sizing it from the parsed key_size is
    # safe.
    probe_key = ctypes.create_string_buffer(max(info.key_size, 1))
    probe_ret = lib.bpf_map_get_next_key(fd, None, ctypes.cast(probe_key, ctypes.c_void_p))
    if probe_ret < 0 and abs(probe_ret) != errno.ENOENT:
        os.close(fd)
        raise BpfError(
            f"Pinned object at '{path}' is not a usable BPF map "
            f"(get_next_key failed: {bindings.libbpf_strerror(abs(probe_ret))})",
            errno=abs(probe_ret),
        )

    return BpfMap(
        owned_fd=fd,
        name=info.name.decode("utf-8").rstrip("\x00"),
        map_type=BpfMapType(info.type),
        key_size=info.key_size,
        value_size=info.value_size,
        max_entries=info.max_entries,
        key_type=key_type,
        value_type=value_type,
    )
