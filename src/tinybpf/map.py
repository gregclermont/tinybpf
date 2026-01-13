"""
BPF map management.

This module provides the BPFMap class for working with BPF maps,
offering a Pythonic dict-like interface with type-safe operations.
"""

from __future__ import annotations

import ctypes
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

from tinybpf._libbpf import get_libbpf
from tinybpf._libbpf.bindings import bpf_map_p
from tinybpf.enums import MapType, MapUpdateFlags
from tinybpf.exceptions import BPFError, BPFMapError, BPFNotFoundError

if TYPE_CHECKING:
    from tinybpf.object import BPFObject

K = TypeVar("K")
V = TypeVar("V")


@dataclass(frozen=True)
class MapInfo:
    """
    Information about a BPF map.

    This dataclass contains metadata about a map's configuration.
    """

    name: str
    type: MapType
    key_size: int
    value_size: int
    max_entries: int
    fd: int

    @property
    def type_name(self) -> str:
        """Human-readable map type name."""
        return self.type.name


class BPFMap:
    """
    Represents a BPF map with dict-like access.

    BPFMap provides a Pythonic interface to BPF maps, supporting
    item access, iteration, and common dict operations. Keys and
    values are handled as raw bytes by default, but can be
    converted using custom serializers.

    Example:
        >>> with tinybpf.load("program.bpf.o") as obj:
        ...     counters = obj.maps["counters"]
        ...     # Set a value
        ...     counters[struct.pack("I", 0)] = struct.pack("Q", 100)
        ...     # Get a value
        ...     value = counters[struct.pack("I", 0)]
        ...     # Iterate over entries
        ...     for key, value in counters.items():
        ...         print(f"Key: {key.hex()}, Value: {value.hex()}")

    For typed access, use TypedBPFMap:
        >>> typed_map = counters.typed(key_format="I", value_format="Q")
        >>> typed_map[0] = 100
        >>> print(typed_map[0])
    """

    def __init__(
        self,
        map_ptr: bpf_map_p,
        obj: BPFObject,
    ) -> None:
        """
        Initialize a BPFMap.

        This should not be called directly. Use BPFObject.maps[]
        to access maps.

        Args:
            map_ptr: Pointer to the underlying bpf_map structure.
            obj: The parent BPFObject.
        """
        self._ptr = map_ptr
        self._obj = obj
        self._libbpf = get_libbpf()
        self._pin_path: Path | None = None

    @property
    def name(self) -> str:
        """The name of this map."""
        return self._libbpf.map_name(self._ptr)

    @property
    def fd(self) -> int:
        """File descriptor for this loaded map."""
        return self._libbpf.map_fd(self._ptr)

    @property
    def type(self) -> MapType:
        """The BPF map type."""
        return MapType(self._libbpf.map_type(self._ptr))

    @property
    def key_size(self) -> int:
        """Size of keys in bytes."""
        return self._libbpf.map_key_size(self._ptr)

    @property
    def value_size(self) -> int:
        """Size of values in bytes."""
        return self._libbpf.map_value_size(self._ptr)

    @property
    def max_entries(self) -> int:
        """Maximum number of entries in this map."""
        return self._libbpf.map_max_entries(self._ptr)

    @property
    def info(self) -> MapInfo:
        """Get map metadata as a MapInfo dataclass."""
        return MapInfo(
            name=self.name,
            type=self.type,
            key_size=self.key_size,
            value_size=self.value_size,
            max_entries=self.max_entries,
            fd=self.fd,
        )

    @property
    def pin_path(self) -> Path | None:
        """Path where this map is pinned, if any."""
        return self._pin_path

    def _validate_key(self, key: bytes) -> bytes:
        """Validate and potentially pad key to correct size."""
        if len(key) < self.key_size:
            # Pad with zeros
            key = key + b"\x00" * (self.key_size - len(key))
        elif len(key) > self.key_size:
            raise BPFMapError(f"Key size {len(key)} exceeds map key size {self.key_size}")
        return key

    def _validate_value(self, value: bytes) -> bytes:
        """Validate and potentially pad value to correct size."""
        if len(value) < self.value_size:
            # Pad with zeros
            value = value + b"\x00" * (self.value_size - len(value))
        elif len(value) > self.value_size:
            raise BPFMapError(f"Value size {len(value)} exceeds map value size {self.value_size}")
        return value

    def lookup(self, key: bytes) -> bytes | None:
        """
        Look up a value by key.

        Args:
            key: The key to look up (as bytes).

        Returns:
            The value as bytes, or None if not found.

        Raises:
            BPFMapError: If the lookup fails for reasons other than key not found.
        """
        key = self._validate_key(key)
        return self._libbpf.map_lookup_elem(self._ptr, key, self.key_size, self.value_size)

    def update(
        self,
        key: bytes,
        value: bytes,
        flags: MapUpdateFlags = MapUpdateFlags.ANY,
    ) -> None:
        """
        Update or insert a key-value pair.

        Args:
            key: The key (as bytes).
            value: The value (as bytes).
            flags: Update flags controlling behavior.

        Raises:
            BPFMapError: If the update fails.
        """
        key = self._validate_key(key)
        value = self._validate_value(value)
        self._libbpf.map_update_elem(
            self._ptr, key, self.key_size, value, self.value_size, int(flags)
        )

    def delete(self, key: bytes) -> None:
        """
        Delete a key from the map.

        Args:
            key: The key to delete (as bytes).

        Raises:
            BPFMapError: If deletion fails for reasons other than key not found.
        """
        key = self._validate_key(key)
        self._libbpf.map_delete_elem(self._ptr, key, self.key_size)

    def keys(self) -> Iterator[bytes]:
        """
        Iterate over all keys in the map.

        Yields:
            Each key as bytes.
        """
        cur_key: bytes | None = None
        while True:
            next_key = self._libbpf.map_get_next_key(self._ptr, cur_key, self.key_size)
            if next_key is None:
                break
            yield next_key
            cur_key = next_key

    def values(self) -> Iterator[bytes]:
        """
        Iterate over all values in the map.

        Yields:
            Each value as bytes.
        """
        for key in self.keys():
            value = self.lookup(key)
            if value is not None:
                yield value

    def items(self) -> Iterator[tuple[bytes, bytes]]:
        """
        Iterate over all key-value pairs in the map.

        Yields:
            Tuples of (key, value) as bytes.
        """
        for key in self.keys():
            value = self.lookup(key)
            if value is not None:
                yield key, value

    def clear(self) -> None:
        """Delete all entries from the map."""
        # Collect keys first to avoid modifying during iteration
        keys_to_delete = list(self.keys())
        for key in keys_to_delete:
            self.delete(key)

    def pin(self, path: str | Path) -> None:
        """
        Pin this map to the BPF filesystem.

        Pinning allows the map to persist after the process exits.

        Args:
            path: Path in the BPF filesystem (typically under /sys/fs/bpf/).

        Raises:
            BPFError: If pinning fails.
        """
        path = Path(path)
        self._libbpf.map_pin(self._ptr, str(path))
        self._pin_path = path

    def unpin(self) -> None:
        """
        Unpin this map from the BPF filesystem.

        Raises:
            BPFError: If unpinning fails or map is not pinned.
        """
        if self._pin_path is None:
            raise BPFError("Map is not pinned")
        self._libbpf.map_unpin(self._ptr, str(self._pin_path))
        self._pin_path = None

    def typed(
        self,
        key_format: str | None = None,
        value_format: str | None = None,
        key_type: type[ctypes.Structure] | None = None,
        value_type: type[ctypes.Structure] | None = None,
    ) -> TypedBPFMap:
        """
        Create a typed view of this map.

        This returns a wrapper that automatically serializes/deserializes
        keys and values using struct format strings or ctypes structures.

        Args:
            key_format: struct format string for keys (e.g., "I" for uint32).
            value_format: struct format string for values (e.g., "Q" for uint64).
            key_type: ctypes Structure type for keys.
            value_type: ctypes Structure type for values.

        Returns:
            A TypedBPFMap wrapper.

        Example:
            >>> typed = my_map.typed(key_format="I", value_format="Q")
            >>> typed[42] = 12345
            >>> print(typed[42])  # 12345
        """
        return TypedBPFMap(
            self,
            key_format=key_format,
            value_format=value_format,
            key_type=key_type,
            value_type=value_type,
        )

    # Dict-like interface
    def __getitem__(self, key: bytes) -> bytes:
        """Get a value by key, raising KeyError if not found."""
        value = self.lookup(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: bytes, value: bytes) -> None:
        """Set a key-value pair."""
        self.update(key, value)

    def __delitem__(self, key: bytes) -> None:
        """Delete a key from the map."""
        self.delete(key)

    def __contains__(self, key: bytes) -> bool:
        """Check if a key exists in the map."""
        return self.lookup(self._validate_key(key)) is not None

    def __iter__(self) -> Iterator[bytes]:
        """Iterate over keys."""
        return self.keys()

    def __len__(self) -> int:
        """Count entries in the map (may be expensive for large maps)."""
        return sum(1 for _ in self.keys())

    def __repr__(self) -> str:
        return (
            f"BPFMap({self.name!r}, type={self.type.name}, "
            f"key_size={self.key_size}, value_size={self.value_size})"
        )


class TypedBPFMap(Generic[K, V]):
    """
    A typed wrapper around BPFMap that handles serialization.

    This class provides automatic conversion between Python types
    and the raw bytes stored in BPF maps.

    Example:
        >>> # Using struct format strings
        >>> typed = map.typed(key_format="I", value_format="Q")
        >>> typed[0] = 100
        >>> print(typed[0])  # 100

        >>> # Using ctypes structures
        >>> class Key(ctypes.Structure):
        ...     _fields_ = [("pid", ctypes.c_uint32)]
        >>> typed = map.typed(key_type=Key, value_format="Q")
    """

    def __init__(
        self,
        bpf_map: BPFMap,
        key_format: str | None = None,
        value_format: str | None = None,
        key_type: type[ctypes.Structure] | None = None,
        value_type: type[ctypes.Structure] | None = None,
    ) -> None:
        """
        Initialize a TypedBPFMap.

        Args:
            bpf_map: The underlying BPFMap.
            key_format: struct format string for keys.
            value_format: struct format string for values.
            key_type: ctypes Structure type for keys.
            value_type: ctypes Structure type for values.
        """
        self._map = bpf_map
        self._key_format = key_format
        self._value_format = value_format
        self._key_type = key_type
        self._value_type = value_type

        # Validate sizes
        if key_format:
            expected = struct.calcsize(key_format)
            if expected != bpf_map.key_size:
                raise ValueError(
                    f"Key format size {expected} doesn't match map key size {bpf_map.key_size}"
                )
        if value_format:
            expected = struct.calcsize(value_format)
            if expected != bpf_map.value_size:
                raise ValueError(
                    f"Value format size {expected} doesn't match "
                    f"map value size {bpf_map.value_size}"
                )
        if key_type:
            expected = ctypes.sizeof(key_type)
            if expected != bpf_map.key_size:
                raise ValueError(
                    f"Key type size {expected} doesn't match map key size {bpf_map.key_size}"
                )
        if value_type:
            expected = ctypes.sizeof(value_type)
            if expected != bpf_map.value_size:
                raise ValueError(
                    f"Value type size {expected} doesn't match map value size {bpf_map.value_size}"
                )

    @property
    def raw(self) -> BPFMap:
        """Access the underlying raw BPFMap."""
        return self._map

    def _serialize_key(self, key: K) -> bytes:
        """Convert a key to bytes."""
        if self._key_type is not None and isinstance(key, ctypes.Structure):
            return bytes(key)
        if self._key_format is not None:
            if isinstance(key, tuple):
                return struct.pack(self._key_format, *key)
            return struct.pack(self._key_format, key)
        if isinstance(key, bytes):
            return key
        raise TypeError(f"Cannot serialize key of type {type(key)}")

    def _deserialize_key(self, data: bytes) -> K:
        """Convert bytes to a key."""
        if self._key_type is not None:
            instance = self._key_type()
            ctypes.memmove(ctypes.addressof(instance), data, len(data))
            return instance  # type: ignore
        if self._key_format is not None:
            result = struct.unpack(self._key_format, data)
            return result[0] if len(result) == 1 else result  # type: ignore
        return data  # type: ignore

    def _serialize_value(self, value: V) -> bytes:
        """Convert a value to bytes."""
        if self._value_type is not None and isinstance(value, ctypes.Structure):
            return bytes(value)
        if self._value_format is not None:
            if isinstance(value, tuple):
                return struct.pack(self._value_format, *value)
            return struct.pack(self._value_format, value)
        if isinstance(value, bytes):
            return value
        raise TypeError(f"Cannot serialize value of type {type(value)}")

    def _deserialize_value(self, data: bytes) -> V:
        """Convert bytes to a value."""
        if self._value_type is not None:
            instance = self._value_type()
            ctypes.memmove(ctypes.addressof(instance), data, len(data))
            return instance  # type: ignore
        if self._value_format is not None:
            result = struct.unpack(self._value_format, data)
            return result[0] if len(result) == 1 else result  # type: ignore
        return data  # type: ignore

    def lookup(self, key: K) -> V | None:
        """Look up a value by key."""
        raw_key = self._serialize_key(key)
        raw_value = self._map.lookup(raw_key)
        if raw_value is None:
            return None
        return self._deserialize_value(raw_value)

    def update(self, key: K, value: V, flags: MapUpdateFlags = MapUpdateFlags.ANY) -> None:
        """Update or insert a key-value pair."""
        raw_key = self._serialize_key(key)
        raw_value = self._serialize_value(value)
        self._map.update(raw_key, raw_value, flags)

    def delete(self, key: K) -> None:
        """Delete a key from the map."""
        raw_key = self._serialize_key(key)
        self._map.delete(raw_key)

    def keys(self) -> Iterator[K]:
        """Iterate over all keys."""
        for raw_key in self._map:
            yield self._deserialize_key(raw_key)

    def values(self) -> Iterator[V]:
        """Iterate over all values."""
        for raw_value in self._map.values():
            yield self._deserialize_value(raw_value)

    def items(self) -> Iterator[tuple[K, V]]:
        """Iterate over all key-value pairs."""
        for raw_key, raw_value in self._map.items():
            yield self._deserialize_key(raw_key), self._deserialize_value(raw_value)

    def __getitem__(self, key: K) -> V:
        """Get a value by key, raising KeyError if not found."""
        value = self.lookup(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: K, value: V) -> None:
        """Set a key-value pair."""
        self.update(key, value)

    def __delitem__(self, key: K) -> None:
        """Delete a key from the map."""
        self.delete(key)

    def __contains__(self, key: K) -> bool:
        """Check if a key exists in the map."""
        return self.lookup(key) is not None

    def __iter__(self) -> Iterator[K]:
        """Iterate over keys."""
        return self.keys()

    def __len__(self) -> int:
        """Count entries in the map."""
        return len(self._map)

    def __repr__(self) -> str:
        return f"TypedBPFMap({self._map!r})"


class BPFMapCollection:
    """
    A dict-like collection of BPF maps from a loaded object.

    This class provides convenient access to maps by name.

    Example:
        >>> maps = obj.maps
        >>> counters = maps["counters"]
        >>> for name in maps:
        ...     print(name, maps[name].type)
    """

    def __init__(self, obj: BPFObject) -> None:
        """Initialize the map collection."""
        self._obj = obj
        self._libbpf = get_libbpf()
        self._cache: dict[str, BPFMap] = {}

    def _iter_raw_maps(self) -> Iterator[bpf_map_p]:
        """Iterate over raw map pointers."""
        map_ptr = self._libbpf.next_map(self._obj._ptr, None)
        while map_ptr:
            yield map_ptr
            map_ptr = self._libbpf.next_map(self._obj._ptr, map_ptr)

    def __getitem__(self, name: str) -> BPFMap:
        """Get a map by name."""
        if name in self._cache:
            return self._cache[name]

        try:
            map_ptr = self._libbpf.find_map_by_name(self._obj._ptr, name)
        except Exception:
            raise BPFNotFoundError(f"Map not found: {name}") from None

        bpf_map = BPFMap(map_ptr, self._obj)
        self._cache[name] = bpf_map
        return bpf_map

    def get(self, name: str, default: BPFMap | None = None) -> BPFMap | None:
        """Get a map by name, returning default if not found."""
        try:
            return self[name]
        except BPFNotFoundError:
            return default

    def __contains__(self, name: str) -> bool:
        """Check if a map with the given name exists."""
        try:
            self._libbpf.find_map_by_name(self._obj._ptr, name)
            return True
        except Exception:
            return False

    def __iter__(self) -> Iterator[str]:
        """Iterate over map names."""
        for map_ptr in self._iter_raw_maps():
            yield self._libbpf.map_name(map_ptr)

    def __len__(self) -> int:
        """Count the number of maps."""
        return sum(1 for _ in self._iter_raw_maps())

    def items(self) -> Iterator[tuple[str, BPFMap]]:
        """Iterate over (name, map) pairs."""
        for name in self:
            yield name, self[name]

    def keys(self) -> Iterator[str]:
        """Iterate over map names."""
        return iter(self)

    def values(self) -> Iterator[BPFMap]:
        """Iterate over maps."""
        for name in self:
            yield self[name]

    def __repr__(self) -> str:
        names = list(self.keys())
        return f"BPFMapCollection({names!r})"
