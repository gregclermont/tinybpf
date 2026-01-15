"""BPF map access and manipulation.

This module provides dict-like access to BPF maps with support for
various key/value types including bytes, integers, and ctypes structures.
"""

from __future__ import annotations

import ctypes
import errno
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from tinybpf._libbpf import bindings
from tinybpf._types import BPF_ANY, BpfError, BpfMapType, MapInfo, _check_err

if TYPE_CHECKING:
    from tinybpf._object import BpfObject

KT = TypeVar("KT")
VT = TypeVar("VT")


class BpfMap(Generic[KT, VT]):
    """A BPF map within a loaded object.

    Provides dict-like access to map elements and iteration support.
    By default, keys and values are treated as raw bytes.
    """

    def __init__(
        self,
        map_ptr: Any,
        obj: BpfObject,
        key_type: type[KT] | None = None,
        value_type: type[VT] | None = None,
    ) -> None:
        self._ptr = map_ptr
        self._obj = obj  # Keep reference to prevent GC
        lib = bindings._get_lib()
        self._name = lib.bpf_map__name(map_ptr).decode("utf-8")
        self._type = BpfMapType(lib.bpf_map__type(map_ptr))
        self._key_size = lib.bpf_map__key_size(map_ptr)
        self._value_size = lib.bpf_map__value_size(map_ptr)
        self._max_entries = lib.bpf_map__max_entries(map_ptr)
        self._key_type = key_type
        self._value_type = value_type

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

    def _check_open(self) -> None:
        """Raise if parent BpfObject is closed."""
        if self._obj._closed:
            raise BpfError("Cannot use map after BpfObject is closed")

    def _to_key_bytes(self, key: KT) -> bytes:
        """Convert key to bytes."""
        if isinstance(key, bytes):
            if len(key) != self._key_size:
                raise ValueError(f"Key size mismatch: got {len(key)}, expected {self._key_size}")
            return key
        if isinstance(key, ctypes.Structure):
            return bytes(key)
        if isinstance(key, int):
            return key.to_bytes(self._key_size, byteorder="little")
        raise TypeError(f"Cannot convert {type(key).__name__} to key bytes")

    def _to_value_bytes(self, value: VT) -> bytes:
        """Convert value to bytes."""
        if isinstance(value, bytes):
            if len(value) != self._value_size:
                raise ValueError(
                    f"Value size mismatch: got {len(value)}, expected {self._value_size}"
                )
            return value
        if isinstance(value, ctypes.Structure):
            return bytes(value)
        if isinstance(value, int):
            return value.to_bytes(self._value_size, byteorder="little")
        raise TypeError(f"Cannot convert {type(value).__name__} to value bytes")

    def _from_key_bytes(self, data: bytes) -> KT:
        """Convert bytes to key type."""
        if self._key_type is None:
            return data  # type: ignore
        if self._key_type is int:
            return int.from_bytes(data, byteorder="little")  # type: ignore
        if issubclass(self._key_type, ctypes.Structure):
            return self._key_type.from_buffer_copy(data)  # type: ignore[return-value]
        return data  # type: ignore

    def _from_value_bytes(self, data: bytes) -> VT:
        """Convert bytes to value type."""
        if self._value_type is None:
            return data  # type: ignore
        if self._value_type is int:
            return int.from_bytes(data, byteorder="little")  # type: ignore
        if issubclass(self._value_type, ctypes.Structure):
            return self._value_type.from_buffer_copy(data)  # type: ignore[return-value]
        return data  # type: ignore

    def lookup(self, key: KT) -> VT | None:
        """Look up a value by key.

        Args:
            key: The key to look up (bytes, int, or ctypes.Structure).

        Returns:
            The value if found, None otherwise.
        """
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

    def update(self, key: KT, value: VT, flags: int = BPF_ANY) -> None:
        """Update a map element.

        Args:
            key: The key to update.
            value: The new value.
            flags: Update flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST).

        Raises:
            BpfError: If update fails.
        """
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
