"""
Low-level ctypes bindings to libbpf.

This module provides typed ctypes wrappers around the essential libbpf
functions for loading BPF objects, managing programs and maps, and
attaching to kernel hooks.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import CDLL


# Opaque pointer types for libbpf structures
# Using lowercase names to match C libbpf naming convention
class _bpf_object(ctypes.Structure):  # noqa: N801
    """Opaque struct bpf_object pointer."""

    pass


class _bpf_program(ctypes.Structure):  # noqa: N801
    """Opaque struct bpf_program pointer."""

    pass


class _bpf_map(ctypes.Structure):  # noqa: N801
    """Opaque struct bpf_map pointer."""

    pass


class _bpf_link(ctypes.Structure):  # noqa: N801
    """Opaque struct bpf_link pointer."""

    pass


# Pointer types
bpf_object_p = ctypes.POINTER(_bpf_object)
bpf_program_p = ctypes.POINTER(_bpf_program)
bpf_map_p = ctypes.POINTER(_bpf_map)
bpf_link_p = ctypes.POINTER(_bpf_link)


class bpf_object_open_opts(ctypes.Structure):  # noqa: N801
    """Options for bpf_object__open_file."""

    _fields_ = [
        ("sz", ctypes.c_size_t),
        ("object_name", ctypes.c_char_p),
        ("relaxed_maps", ctypes.c_bool),
        ("pin_root_path", ctypes.c_char_p),
        ("kconfig", ctypes.c_char_p),
        ("btf_custom_path", ctypes.c_char_p),
        ("kernel_log_buf", ctypes.c_char_p),
        ("kernel_log_size", ctypes.c_size_t),
        ("kernel_log_level", ctypes.c_uint32),
        ("bpf_token_path", ctypes.c_char_p),
    ]


class bpf_map_info(ctypes.Structure):  # noqa: N801
    """BPF map info structure returned by bpf_map_get_info_by_fd."""

    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("name", ctypes.c_char * 16),
        ("ifindex", ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", ctypes.c_uint32),
        ("netns_dev", ctypes.c_uint64),
        ("netns_ino", ctypes.c_uint64),
        ("btf_id", ctypes.c_uint32),
        ("btf_key_type_id", ctypes.c_uint32),
        ("btf_value_type_id", ctypes.c_uint32),
        ("map_extra", ctypes.c_uint64),
    ]


class LibBPFError(Exception):
    """Exception raised when libbpf operations fail."""

    def __init__(self, message: str, errno_val: int = 0) -> None:
        self.errno = errno_val
        if errno_val:
            message = f"{message}: {os.strerror(errno_val)} (errno={errno_val})"
        super().__init__(message)


def _find_libbpf_path() -> Path:
    """
    Find the libbpf shared library path.

    First checks for a bundled library in the package, then falls back
    to system-installed versions.
    """
    # Try bundled library first (for wheel distribution)
    try:
        if hasattr(resources, "files"):
            # Python 3.9+
            pkg_files = resources.files("tinybpf._libbpf")
            for item in pkg_files.iterdir():
                if item.name.startswith("libbpf.so"):
                    # Use as_file for proper resource extraction
                    return Path(str(item))
        else:
            # Fallback for older Python
            with resources.path("tinybpf._libbpf", "__init__.py") as p:
                pkg_dir = p.parent
                for item in pkg_dir.iterdir():
                    if item.name.startswith("libbpf.so"):
                        return item
    except (TypeError, FileNotFoundError, ModuleNotFoundError):
        pass

    # Try to find system libbpf
    lib_path = ctypes.util.find_library("bpf")
    if lib_path:
        return Path(lib_path)

    # Common system paths
    common_paths = [
        "/usr/lib/x86_64-linux-gnu/libbpf.so.1",
        "/usr/lib64/libbpf.so.1",
        "/usr/lib/libbpf.so.1",
        "/usr/local/lib/libbpf.so.1",
        "/usr/lib/x86_64-linux-gnu/libbpf.so.0",
        "/usr/lib64/libbpf.so.0",
        "/usr/lib/libbpf.so.0",
    ]

    for path_str in common_paths:
        path = Path(path_str)
        if path.exists():
            return path

    raise LibBPFError(
        "Could not find libbpf shared library. "
        "Install libbpf-dev or use a wheel with bundled libbpf."
    )


class LibBPF:
    """
    Wrapper class providing typed access to libbpf functions.

    This class loads the libbpf shared library and sets up ctypes
    function signatures for type safety.
    """

    def __init__(self, lib_path: Path | str | None = None) -> None:
        """
        Initialize the libbpf wrapper.

        Args:
            lib_path: Optional explicit path to libbpf.so. If not provided,
                     will search for bundled or system library.
        """
        if lib_path is None:
            lib_path = _find_libbpf_path()

        self._lib_path = Path(lib_path)
        self._lib: CDLL = ctypes.CDLL(str(self._lib_path), use_errno=True)
        self._setup_functions()

    def _setup_functions(self) -> None:
        """Set up ctypes function signatures."""
        lib = self._lib

        # === Object operations ===

        # struct bpf_object *bpf_object__open(const char *path)
        lib.bpf_object__open.argtypes = [ctypes.c_char_p]
        lib.bpf_object__open.restype = bpf_object_p

        # struct bpf_object *bpf_object__open_file(const char *path,
        #                                          const struct bpf_object_open_opts *opts)
        lib.bpf_object__open_file.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(bpf_object_open_opts),
        ]
        lib.bpf_object__open_file.restype = bpf_object_p

        # int bpf_object__load(struct bpf_object *obj)
        lib.bpf_object__load.argtypes = [bpf_object_p]
        lib.bpf_object__load.restype = ctypes.c_int

        # void bpf_object__close(struct bpf_object *obj)
        lib.bpf_object__close.argtypes = [bpf_object_p]
        lib.bpf_object__close.restype = None

        # const char *bpf_object__name(const struct bpf_object *obj)
        lib.bpf_object__name.argtypes = [bpf_object_p]
        lib.bpf_object__name.restype = ctypes.c_char_p

        # === Program operations ===

        # struct bpf_program *bpf_object__find_program_by_name(
        #     const struct bpf_object *obj, const char *name)
        lib.bpf_object__find_program_by_name.argtypes = [bpf_object_p, ctypes.c_char_p]
        lib.bpf_object__find_program_by_name.restype = bpf_program_p

        # struct bpf_program *bpf_object__next_program(
        #     const struct bpf_object *obj, struct bpf_program *prog)
        lib.bpf_object__next_program.argtypes = [bpf_object_p, bpf_program_p]
        lib.bpf_object__next_program.restype = bpf_program_p

        # const char *bpf_program__name(const struct bpf_program *prog)
        lib.bpf_program__name.argtypes = [bpf_program_p]
        lib.bpf_program__name.restype = ctypes.c_char_p

        # const char *bpf_program__section_name(const struct bpf_program *prog)
        lib.bpf_program__section_name.argtypes = [bpf_program_p]
        lib.bpf_program__section_name.restype = ctypes.c_char_p

        # int bpf_program__fd(const struct bpf_program *prog)
        lib.bpf_program__fd.argtypes = [bpf_program_p]
        lib.bpf_program__fd.restype = ctypes.c_int

        # enum bpf_prog_type bpf_program__type(const struct bpf_program *prog)
        lib.bpf_program__type.argtypes = [bpf_program_p]
        lib.bpf_program__type.restype = ctypes.c_int

        # === Program attachment ===

        # struct bpf_link *bpf_program__attach(const struct bpf_program *prog)
        lib.bpf_program__attach.argtypes = [bpf_program_p]
        lib.bpf_program__attach.restype = bpf_link_p

        # struct bpf_link *bpf_program__attach_kprobe(
        #     const struct bpf_program *prog, bool retprobe, const char *func_name)
        lib.bpf_program__attach_kprobe.argtypes = [
            bpf_program_p,
            ctypes.c_bool,
            ctypes.c_char_p,
        ]
        lib.bpf_program__attach_kprobe.restype = bpf_link_p

        # struct bpf_link *bpf_program__attach_tracepoint(
        #     const struct bpf_program *prog,
        #     const char *tp_category, const char *tp_name)
        lib.bpf_program__attach_tracepoint.argtypes = [
            bpf_program_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        lib.bpf_program__attach_tracepoint.restype = bpf_link_p

        # struct bpf_link *bpf_program__attach_uprobe(
        #     const struct bpf_program *prog, bool retprobe,
        #     pid_t pid, const char *binary_path, size_t func_offset)
        lib.bpf_program__attach_uprobe.argtypes = [
            bpf_program_p,
            ctypes.c_bool,
            ctypes.c_int,  # pid_t
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.bpf_program__attach_uprobe.restype = bpf_link_p

        # struct bpf_link *bpf_program__attach_raw_tracepoint(
        #     const struct bpf_program *prog, const char *tp_name)
        lib.bpf_program__attach_raw_tracepoint.argtypes = [
            bpf_program_p,
            ctypes.c_char_p,
        ]
        lib.bpf_program__attach_raw_tracepoint.restype = bpf_link_p

        # struct bpf_link *bpf_program__attach_perf_event(
        #     const struct bpf_program *prog, int pfd)
        lib.bpf_program__attach_perf_event.argtypes = [bpf_program_p, ctypes.c_int]
        lib.bpf_program__attach_perf_event.restype = bpf_link_p

        # === Link operations ===

        # int bpf_link__destroy(struct bpf_link *link)
        lib.bpf_link__destroy.argtypes = [bpf_link_p]
        lib.bpf_link__destroy.restype = ctypes.c_int

        # int bpf_link__fd(const struct bpf_link *link)
        lib.bpf_link__fd.argtypes = [bpf_link_p]
        lib.bpf_link__fd.restype = ctypes.c_int

        # int bpf_link__pin(struct bpf_link *link, const char *path)
        lib.bpf_link__pin.argtypes = [bpf_link_p, ctypes.c_char_p]
        lib.bpf_link__pin.restype = ctypes.c_int

        # int bpf_link__unpin(struct bpf_link *link)
        lib.bpf_link__unpin.argtypes = [bpf_link_p]
        lib.bpf_link__unpin.restype = ctypes.c_int

        # === Map operations ===

        # struct bpf_map *bpf_object__find_map_by_name(
        #     const struct bpf_object *obj, const char *name)
        lib.bpf_object__find_map_by_name.argtypes = [bpf_object_p, ctypes.c_char_p]
        lib.bpf_object__find_map_by_name.restype = bpf_map_p

        # struct bpf_map *bpf_object__next_map(
        #     const struct bpf_object *obj, const struct bpf_map *map)
        lib.bpf_object__next_map.argtypes = [bpf_object_p, bpf_map_p]
        lib.bpf_object__next_map.restype = bpf_map_p

        # const char *bpf_map__name(const struct bpf_map *map)
        lib.bpf_map__name.argtypes = [bpf_map_p]
        lib.bpf_map__name.restype = ctypes.c_char_p

        # int bpf_map__fd(const struct bpf_map *map)
        lib.bpf_map__fd.argtypes = [bpf_map_p]
        lib.bpf_map__fd.restype = ctypes.c_int

        # __u32 bpf_map__type(const struct bpf_map *map)
        lib.bpf_map__type.argtypes = [bpf_map_p]
        lib.bpf_map__type.restype = ctypes.c_uint32

        # __u32 bpf_map__key_size(const struct bpf_map *map)
        lib.bpf_map__key_size.argtypes = [bpf_map_p]
        lib.bpf_map__key_size.restype = ctypes.c_uint32

        # __u32 bpf_map__value_size(const struct bpf_map *map)
        lib.bpf_map__value_size.argtypes = [bpf_map_p]
        lib.bpf_map__value_size.restype = ctypes.c_uint32

        # __u32 bpf_map__max_entries(const struct bpf_map *map)
        lib.bpf_map__max_entries.argtypes = [bpf_map_p]
        lib.bpf_map__max_entries.restype = ctypes.c_uint32

        # int bpf_map__pin(struct bpf_map *map, const char *path)
        lib.bpf_map__pin.argtypes = [bpf_map_p, ctypes.c_char_p]
        lib.bpf_map__pin.restype = ctypes.c_int

        # int bpf_map__unpin(struct bpf_map *map, const char *path)
        lib.bpf_map__unpin.argtypes = [bpf_map_p, ctypes.c_char_p]
        lib.bpf_map__unpin.restype = ctypes.c_int

        # === Map element operations (using map pointer) ===

        # int bpf_map__lookup_elem(const struct bpf_map *map,
        #                          const void *key, size_t key_sz,
        #                          void *value, size_t value_sz, __u64 flags)
        lib.bpf_map__lookup_elem.argtypes = [
            bpf_map_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
        ]
        lib.bpf_map__lookup_elem.restype = ctypes.c_int

        # int bpf_map__update_elem(const struct bpf_map *map,
        #                          const void *key, size_t key_sz,
        #                          const void *value, size_t value_sz, __u64 flags)
        lib.bpf_map__update_elem.argtypes = [
            bpf_map_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
        ]
        lib.bpf_map__update_elem.restype = ctypes.c_int

        # int bpf_map__delete_elem(const struct bpf_map *map,
        #                          const void *key, size_t key_sz, __u64 flags)
        lib.bpf_map__delete_elem.argtypes = [
            bpf_map_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
        ]
        lib.bpf_map__delete_elem.restype = ctypes.c_int

        # int bpf_map__get_next_key(const struct bpf_map *map,
        #                           const void *cur_key, void *next_key, size_t key_sz)
        lib.bpf_map__get_next_key.argtypes = [
            bpf_map_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.bpf_map__get_next_key.restype = ctypes.c_int

        # === Logging ===

        # typedef int (*libbpf_print_fn_t)(enum libbpf_print_level level,
        #                                  const char *format, va_list ap)
        # libbpf_print_fn_t libbpf_set_print(libbpf_print_fn_t fn)
        lib.libbpf_set_print.argtypes = [ctypes.c_void_p]
        lib.libbpf_set_print.restype = ctypes.c_void_p

        # === Error handling ===

        # int libbpf_get_error(const void *ptr)
        lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
        lib.libbpf_get_error.restype = ctypes.c_long

    @property
    def lib(self) -> CDLL:
        """Get the underlying ctypes library."""
        return self._lib

    # === High-level wrapper methods ===

    def set_print(self, callback: ctypes.c_void_p | None = None) -> None:
        """
        Set the libbpf print callback.

        Pass None to disable libbpf logging output.
        """
        self._lib.libbpf_set_print(callback)

    def get_error(self, ptr: ctypes.c_void_p) -> int:
        """Get the error code from a libbpf pointer return value."""
        return int(self._lib.libbpf_get_error(ptr))

    def check_error(self, ptr: ctypes.c_void_p, operation: str) -> None:
        """Check if a pointer return value indicates an error."""
        err = self.get_error(ptr)
        if err:
            raise LibBPFError(f"{operation} failed", -err)

    # Object operations
    def object_open(self, path: str | Path) -> bpf_object_p:
        """Open a BPF object file."""
        path_bytes = str(path).encode("utf-8")
        obj = self._lib.bpf_object__open(path_bytes)
        if not obj:
            err = ctypes.get_errno()
            raise LibBPFError(f"Failed to open BPF object: {path}", err)
        self.check_error(obj, f"bpf_object__open({path})")
        return obj

    def object_load(self, obj: bpf_object_p) -> None:
        """Load a BPF object into the kernel."""
        ret = self._lib.bpf_object__load(obj)
        if ret < 0:
            raise LibBPFError("Failed to load BPF object", -ret)

    def object_close(self, obj: bpf_object_p) -> None:
        """Close a BPF object and free resources."""
        self._lib.bpf_object__close(obj)

    def object_name(self, obj: bpf_object_p) -> str:
        """Get the name of a BPF object."""
        name = self._lib.bpf_object__name(obj)
        return name.decode("utf-8") if name else ""

    # Program operations
    def find_program_by_name(self, obj: bpf_object_p, name: str) -> bpf_program_p:
        """Find a program by name in a BPF object."""
        name_bytes = name.encode("utf-8")
        prog = self._lib.bpf_object__find_program_by_name(obj, name_bytes)
        if not prog:
            raise LibBPFError(f"Program not found: {name}")
        return prog

    def next_program(self, obj: bpf_object_p, prog: bpf_program_p | None) -> bpf_program_p | None:
        """Get the next program in a BPF object."""
        result = self._lib.bpf_object__next_program(obj, prog)
        return result if result else None

    def program_name(self, prog: bpf_program_p) -> str:
        """Get the name of a BPF program."""
        name = self._lib.bpf_program__name(prog)
        return name.decode("utf-8") if name else ""

    def program_section_name(self, prog: bpf_program_p) -> str:
        """Get the section name of a BPF program."""
        name = self._lib.bpf_program__section_name(prog)
        return name.decode("utf-8") if name else ""

    def program_fd(self, prog: bpf_program_p) -> int:
        """Get the file descriptor of a loaded BPF program."""
        return int(self._lib.bpf_program__fd(prog))

    def program_type(self, prog: bpf_program_p) -> int:
        """Get the program type."""
        return int(self._lib.bpf_program__type(prog))

    # Attachment operations
    def attach_program(self, prog: bpf_program_p) -> bpf_link_p:
        """Auto-attach a program based on its section name."""
        link = self._lib.bpf_program__attach(prog)
        if not link:
            err = ctypes.get_errno()
            raise LibBPFError("Failed to attach program", err)
        self.check_error(link, "bpf_program__attach")
        return link

    def attach_kprobe(
        self, prog: bpf_program_p, func_name: str, retprobe: bool = False
    ) -> bpf_link_p:
        """Attach a program to a kprobe."""
        func_bytes = func_name.encode("utf-8")
        link = self._lib.bpf_program__attach_kprobe(prog, retprobe, func_bytes)
        if not link:
            err = ctypes.get_errno()
            raise LibBPFError(f"Failed to attach kprobe: {func_name}", err)
        self.check_error(link, f"bpf_program__attach_kprobe({func_name})")
        return link

    def attach_tracepoint(self, prog: bpf_program_p, category: str, name: str) -> bpf_link_p:
        """Attach a program to a tracepoint."""
        cat_bytes = category.encode("utf-8")
        name_bytes = name.encode("utf-8")
        link = self._lib.bpf_program__attach_tracepoint(prog, cat_bytes, name_bytes)
        if not link:
            err = ctypes.get_errno()
            raise LibBPFError(f"Failed to attach tracepoint: {category}/{name}", err)
        self.check_error(link, f"bpf_program__attach_tracepoint({category}/{name})")
        return link

    def attach_uprobe(
        self,
        prog: bpf_program_p,
        binary_path: str,
        func_offset: int,
        pid: int = -1,
        retprobe: bool = False,
    ) -> bpf_link_p:
        """Attach a program to a uprobe."""
        path_bytes = binary_path.encode("utf-8")
        link = self._lib.bpf_program__attach_uprobe(prog, retprobe, pid, path_bytes, func_offset)
        if not link:
            err = ctypes.get_errno()
            raise LibBPFError(f"Failed to attach uprobe: {binary_path}+{func_offset}", err)
        self.check_error(link, f"bpf_program__attach_uprobe({binary_path})")
        return link

    def attach_raw_tracepoint(self, prog: bpf_program_p, tp_name: str) -> bpf_link_p:
        """Attach a program to a raw tracepoint."""
        name_bytes = tp_name.encode("utf-8")
        link = self._lib.bpf_program__attach_raw_tracepoint(prog, name_bytes)
        if not link:
            err = ctypes.get_errno()
            raise LibBPFError(f"Failed to attach raw tracepoint: {tp_name}", err)
        self.check_error(link, f"bpf_program__attach_raw_tracepoint({tp_name})")
        return link

    def attach_perf_event(self, prog: bpf_program_p, pfd: int) -> bpf_link_p:
        """Attach a program to a perf event file descriptor."""
        link = self._lib.bpf_program__attach_perf_event(prog, pfd)
        if not link:
            err = ctypes.get_errno()
            raise LibBPFError(f"Failed to attach perf event: fd={pfd}", err)
        self.check_error(link, "bpf_program__attach_perf_event")
        return link

    # Link operations
    def link_destroy(self, link: bpf_link_p) -> None:
        """Destroy a BPF link and detach the program."""
        ret = self._lib.bpf_link__destroy(link)
        if ret < 0:
            raise LibBPFError("Failed to destroy link", -ret)

    def link_fd(self, link: bpf_link_p) -> int:
        """Get the file descriptor of a link."""
        return int(self._lib.bpf_link__fd(link))

    def link_pin(self, link: bpf_link_p, path: str) -> None:
        """Pin a link to the BPF filesystem."""
        path_bytes = path.encode("utf-8")
        ret = self._lib.bpf_link__pin(link, path_bytes)
        if ret < 0:
            raise LibBPFError(f"Failed to pin link to {path}", -ret)

    def link_unpin(self, link: bpf_link_p) -> None:
        """Unpin a link from the BPF filesystem."""
        ret = self._lib.bpf_link__unpin(link)
        if ret < 0:
            raise LibBPFError("Failed to unpin link", -ret)

    # Map operations
    def find_map_by_name(self, obj: bpf_object_p, name: str) -> bpf_map_p:
        """Find a map by name in a BPF object."""
        name_bytes = name.encode("utf-8")
        map_ptr = self._lib.bpf_object__find_map_by_name(obj, name_bytes)
        if not map_ptr:
            raise LibBPFError(f"Map not found: {name}")
        return map_ptr

    def next_map(self, obj: bpf_object_p, map_ptr: bpf_map_p | None) -> bpf_map_p | None:
        """Get the next map in a BPF object."""
        result = self._lib.bpf_object__next_map(obj, map_ptr)
        return result if result else None

    def map_name(self, map_ptr: bpf_map_p) -> str:
        """Get the name of a BPF map."""
        name = self._lib.bpf_map__name(map_ptr)
        return name.decode("utf-8") if name else ""

    def map_fd(self, map_ptr: bpf_map_p) -> int:
        """Get the file descriptor of a loaded BPF map."""
        return int(self._lib.bpf_map__fd(map_ptr))

    def map_type(self, map_ptr: bpf_map_p) -> int:
        """Get the type of a BPF map."""
        return int(self._lib.bpf_map__type(map_ptr))

    def map_key_size(self, map_ptr: bpf_map_p) -> int:
        """Get the key size of a BPF map."""
        return int(self._lib.bpf_map__key_size(map_ptr))

    def map_value_size(self, map_ptr: bpf_map_p) -> int:
        """Get the value size of a BPF map."""
        return int(self._lib.bpf_map__value_size(map_ptr))

    def map_max_entries(self, map_ptr: bpf_map_p) -> int:
        """Get the maximum number of entries in a BPF map."""
        return int(self._lib.bpf_map__max_entries(map_ptr))

    def map_pin(self, map_ptr: bpf_map_p, path: str) -> None:
        """Pin a map to the BPF filesystem."""
        path_bytes = path.encode("utf-8")
        ret = self._lib.bpf_map__pin(map_ptr, path_bytes)
        if ret < 0:
            raise LibBPFError(f"Failed to pin map to {path}", -ret)

    def map_unpin(self, map_ptr: bpf_map_p, path: str) -> None:
        """Unpin a map from the BPF filesystem."""
        path_bytes = path.encode("utf-8")
        ret = self._lib.bpf_map__unpin(map_ptr, path_bytes)
        if ret < 0:
            raise LibBPFError(f"Failed to unpin map from {path}", -ret)

    # Map element operations
    def map_lookup_elem(
        self,
        map_ptr: bpf_map_p,
        key: bytes,
        key_size: int,
        value_size: int,
    ) -> bytes | None:
        """Look up an element in a map."""
        value = ctypes.create_string_buffer(value_size)
        ret = self._lib.bpf_map__lookup_elem(
            map_ptr,
            key,
            key_size,
            value,
            value_size,
            0,  # flags
        )
        if ret < 0:
            if ctypes.get_errno() == errno.ENOENT:
                return None
            raise LibBPFError("Failed to lookup map element", -ret)
        return value.raw

    def map_update_elem(
        self,
        map_ptr: bpf_map_p,
        key: bytes,
        key_size: int,
        value: bytes,
        value_size: int,
        flags: int = 0,
    ) -> None:
        """Update an element in a map."""
        ret = self._lib.bpf_map__update_elem(
            map_ptr,
            key,
            key_size,
            value,
            value_size,
            flags,
        )
        if ret < 0:
            raise LibBPFError("Failed to update map element", -ret)

    def map_delete_elem(
        self,
        map_ptr: bpf_map_p,
        key: bytes,
        key_size: int,
    ) -> None:
        """Delete an element from a map."""
        ret = self._lib.bpf_map__delete_elem(map_ptr, key, key_size, 0)
        if ret < 0 and ctypes.get_errno() != errno.ENOENT:
            raise LibBPFError("Failed to delete map element", -ret)

    def map_get_next_key(
        self,
        map_ptr: bpf_map_p,
        cur_key: bytes | None,
        key_size: int,
    ) -> bytes | None:
        """Get the next key in a map iteration."""
        next_key = ctypes.create_string_buffer(key_size)
        ret = self._lib.bpf_map__get_next_key(
            map_ptr,
            cur_key,
            next_key,
            key_size,
        )
        if ret < 0:
            if ctypes.get_errno() == errno.ENOENT:
                return None
            raise LibBPFError("Failed to get next map key", -ret)
        return next_key.raw


# Singleton instance
_libbpf_instance: LibBPF | None = None


def get_libbpf() -> LibBPF:
    """
    Get the global libbpf instance.

    This is lazily initialized on first access and reused for
    subsequent calls.
    """
    global _libbpf_instance
    if _libbpf_instance is None:
        _libbpf_instance = LibBPF()
        # Disable verbose libbpf logging by default
        _libbpf_instance.set_print(None)
    return _libbpf_instance
