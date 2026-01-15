"""Tests for BPF map operations.

Run with: sudo pytest tests/test_maps.py -v
"""

from pathlib import Path

import pytest

import tinybpf
from conftest import requires_root

pytestmark = requires_root


class TestBpfMaps:
    """Tests for BPF map operations."""

    def test_maps_accessible(self, test_maps_bpf_path: Path) -> None:
        """Maps are accessible by name."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            assert "pid_counts" in obj.maps
            assert "counters" in obj.maps
            assert "percpu_stats" in obj.maps

    def test_map_info(self, test_maps_bpf_path: Path) -> None:
        """MapInfo dataclass contains correct data."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            assert hash_map.type == tinybpf.BpfMapType.HASH
            assert hash_map.key_size == 4  # __u32
            assert hash_map.value_size == 8  # __u64
            assert hash_map.max_entries == 1024

            array_map = obj.map("counters")
            assert array_map.type == tinybpf.BpfMapType.ARRAY
            assert array_map.max_entries == 16

    def test_map_update_and_lookup(self, test_maps_bpf_path: Path) -> None:
        """Can update and lookup map elements."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")

            # Use integer keys/values (converted to bytes)
            key = 12345
            value = 42

            # Update
            hash_map.update(key.to_bytes(4, "little"), value.to_bytes(8, "little"))

            # Lookup
            result = hash_map.lookup(key.to_bytes(4, "little"))
            assert result is not None
            assert int.from_bytes(result, "little") == 42

            # Delete
            assert hash_map.delete(key.to_bytes(4, "little"))
            assert hash_map.lookup(key.to_bytes(4, "little")) is None

    def test_map_dict_interface(self, test_maps_bpf_path: Path) -> None:
        """Map supports dict-like interface."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            key = (99999).to_bytes(4, "little")
            value = (100).to_bytes(8, "little")

            # __setitem__
            hash_map[key] = value

            # __getitem__
            assert hash_map[key] == value

            # __contains__
            assert key in hash_map

            # __delitem__
            del hash_map[key]
            assert key not in hash_map

            # KeyError on missing
            with pytest.raises(KeyError):
                _ = hash_map[key]

    def test_map_iteration(self, test_maps_bpf_path: Path) -> None:
        """Can iterate over map entries."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")

            # Insert some entries
            for i in range(5):
                key = (1000 + i).to_bytes(4, "little")
                value = (i * 10).to_bytes(8, "little")
                hash_map[key] = value

            # keys()
            keys = list(hash_map.keys())
            assert len(keys) >= 5

            # values()
            values = list(hash_map.values())
            assert len(values) >= 5

            # items()
            items = list(hash_map.items())
            assert len(items) >= 5

            # Clean up
            for i in range(5):
                key = (1000 + i).to_bytes(4, "little")
                hash_map.delete(key)

    def test_array_map_operations(self, test_maps_bpf_path: Path) -> None:
        """Array maps work correctly."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            array_map = obj.map("counters")

            # Arrays have fixed indices
            idx = (0).to_bytes(4, "little")
            value = (12345).to_bytes(8, "little")

            array_map[idx] = value
            assert array_map[idx] == value

            # Array maps always have all keys (can't delete)
            # But we can set to zero
            array_map[idx] = (0).to_bytes(8, "little")


class TestBpfMapErrors:
    """Tests for BPF map error handling."""

    def test_empty_map_iteration(self, test_maps_bpf_path: Path) -> None:
        """Iterating an empty map should yield nothing."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            # Ensure map is empty (delete any existing keys)
            for key in list(hash_map.keys()):
                hash_map.delete(key)
            # Verify iteration yields nothing
            assert list(hash_map.keys()) == []
            assert list(hash_map.values()) == []
            assert list(hash_map.items()) == []

    def test_map_update_exceeds_max_entries(self, test_maps_bpf_path: Path) -> None:
        """Exceeding map max_entries should raise BpfError."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            max_entries = hash_map.max_entries

            # Fill the map to capacity
            inserted_keys = []
            for i in range(max_entries):
                key = (i + 100000).to_bytes(4, "little")
                value = (i).to_bytes(8, "little")
                hash_map.update(key, value, tinybpf.BPF_NOEXIST)
                inserted_keys.append(key)

            try:
                # Try to insert one more - should fail
                overflow_key = (max_entries + 100000).to_bytes(4, "little")
                with pytest.raises(tinybpf.BpfError):
                    hash_map.update(overflow_key, b"\x00" * 8, tinybpf.BPF_NOEXIST)
            finally:
                # Clean up
                for key in inserted_keys:
                    hash_map.delete(key)

    def test_map_use_after_close(self, test_maps_bpf_path: Path) -> None:
        """Using map after BpfObject.close() should raise BpfError."""
        obj = tinybpf.load(test_maps_bpf_path)
        hash_map = obj.map("pid_counts")
        obj.close()

        with pytest.raises(tinybpf.BpfError, match="closed"):
            hash_map.lookup(b"\x00" * 4)

    def test_map_iteration_after_close(self, test_maps_bpf_path: Path) -> None:
        """Iterating map after BpfObject.close() should raise BpfError."""
        obj = tinybpf.load(test_maps_bpf_path)
        hash_map = obj.map("pid_counts")
        obj.close()

        with pytest.raises(tinybpf.BpfError, match="closed"):
            list(hash_map.keys())


class TestPinnedMaps:
    """Tests for pinned BPF maps."""

    @pytest.fixture
    def pin_path(self) -> str:
        """Return a path in /sys/fs/bpf for pinning tests, cleaned up after."""
        path = "/sys/fs/bpf/tinybpf_test_pinned"
        yield path
        # Cleanup: remove if it exists
        p = Path(path)
        if p.exists():
            p.unlink()

    def test_pin_map(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Can pin a map to bpffs."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            hash_map.pin(pin_path)
            assert Path(pin_path).exists()

    def test_unpin_map(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Can unpin a previously pinned map."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            hash_map = obj.map("pid_counts")
            hash_map.pin(pin_path)
            assert Path(pin_path).exists()

            hash_map.unpin(pin_path)
            assert not Path(pin_path).exists()

    def test_open_pinned_map(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Can open a pinned map and read its metadata."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            original = obj.map("pid_counts")
            original.pin(pin_path)

            # Open the pinned map
            with tinybpf.open_pinned_map(pin_path) as pinned:
                assert pinned.name == "pid_counts"
                assert pinned.type == tinybpf.BpfMapType.HASH
                assert pinned.key_size == original.key_size
                assert pinned.value_size == original.value_size
                assert pinned.max_entries == original.max_entries
                assert pinned.is_standalone

    def test_pinned_map_operations(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Can perform CRUD operations on a pinned map."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            original = obj.map("pid_counts")
            original.pin(pin_path)

        # Open separately and perform operations
        with tinybpf.open_pinned_map(pin_path) as pinned:
            key = (88888).to_bytes(4, "little")
            value = (999).to_bytes(8, "little")

            # Update
            pinned[key] = value

            # Lookup
            assert pinned[key] == value
            assert key in pinned

            # Delete
            del pinned[key]
            assert key not in pinned

    def test_pinned_map_data_persists(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Data written to pinned map persists across opens."""
        key = (77777).to_bytes(4, "little")
        value = (12345).to_bytes(8, "little")

        # Pin and write data
        with tinybpf.load(test_maps_bpf_path) as obj:
            original = obj.map("pid_counts")
            original[key] = value
            original.pin(pin_path)

        # Open pinned map and verify data persists
        with tinybpf.open_pinned_map(pin_path) as pinned:
            assert pinned[key] == value
            # Clean up
            del pinned[key]

    def test_pinned_map_iteration(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Can iterate over entries in a pinned map."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            original = obj.map("pid_counts")
            # Add some entries
            for i in range(3):
                key = (50000 + i).to_bytes(4, "little")
                value = (i * 100).to_bytes(8, "little")
                original[key] = value
            original.pin(pin_path)

        # Open and iterate
        with tinybpf.open_pinned_map(pin_path) as pinned:
            keys = list(pinned.keys())
            assert len(keys) >= 3
            items = list(pinned.items())
            assert len(items) >= 3

            # Clean up
            for i in range(3):
                key = (50000 + i).to_bytes(4, "little")
                pinned.delete(key)

    def test_pinned_map_use_after_close(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Using pinned map after close() should raise BpfError."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            obj.map("pid_counts").pin(pin_path)

        pinned = tinybpf.open_pinned_map(pin_path)
        pinned.close()

        with pytest.raises(tinybpf.BpfError, match="closed"):
            pinned.lookup(b"\x00" * 4)

    def test_pin_standalone_map_raises(self, test_maps_bpf_path: Path, pin_path: str) -> None:
        """Pinning a standalone map should raise BpfError."""
        with tinybpf.load(test_maps_bpf_path) as obj:
            obj.map("pid_counts").pin(pin_path)

        with tinybpf.open_pinned_map(pin_path) as pinned:
            with pytest.raises(tinybpf.BpfError, match="standalone"):
                pinned.pin("/sys/fs/bpf/another_path")

    def test_open_nonexistent_pinned_map(self) -> None:
        """Opening a non-existent pinned path should raise BpfError."""
        with pytest.raises(tinybpf.BpfError):
            tinybpf.open_pinned_map("/sys/fs/bpf/does_not_exist")
