"""ctypes bindings for libbpf."""

from __future__ import annotations

import ctypes
import ctypes.util
from pathlib import Path

_lib: ctypes.CDLL | None = None
_initialized: bool = False


# Opaque pointer types for libbpf structures
class _bpf_object(ctypes.Structure):
    """Opaque libbpf bpf_object structure."""

    pass


class _bpf_program(ctypes.Structure):
    """Opaque libbpf bpf_program structure."""

    pass


class _bpf_map(ctypes.Structure):
    """Opaque libbpf bpf_map structure."""

    pass


class _bpf_link(ctypes.Structure):
    """Opaque libbpf bpf_link structure."""

    pass


class _ring_buffer(ctypes.Structure):
    """Opaque libbpf ring_buffer structure."""

    pass


class _perf_buffer(ctypes.Structure):
    """Opaque libbpf perf_buffer structure."""

    pass


# Pointer types
bpf_object_p = ctypes.POINTER(_bpf_object)
bpf_program_p = ctypes.POINTER(_bpf_program)
bpf_map_p = ctypes.POINTER(_bpf_map)
bpf_link_p = ctypes.POINTER(_bpf_link)
ring_buffer_p = ctypes.POINTER(_ring_buffer)
perf_buffer_p = ctypes.POINTER(_perf_buffer)

# Callback type for ring buffer: int (*)(void *ctx, void *data, size_t size)
RING_BUFFER_SAMPLE_FN = ctypes.CFUNCTYPE(
    ctypes.c_int,  # return
    ctypes.c_void_p,  # ctx
    ctypes.c_void_p,  # data
    ctypes.c_size_t,  # size
)

# Callback types for perf buffer (note: return void, not int)
PERF_BUFFER_SAMPLE_FN = ctypes.CFUNCTYPE(
    None,  # return void
    ctypes.c_void_p,  # ctx
    ctypes.c_int,  # cpu
    ctypes.c_void_p,  # data
    ctypes.c_uint32,  # size
)

PERF_BUFFER_LOST_FN = ctypes.CFUNCTYPE(
    None,  # return void
    ctypes.c_void_p,  # ctx
    ctypes.c_int,  # cpu
    ctypes.c_uint64,  # lost_cnt
)


def _setup_function_signatures(lib: ctypes.CDLL) -> None:
    """Configure ctypes function signatures for libbpf."""
    # Version
    lib.libbpf_version_string.argtypes = []
    lib.libbpf_version_string.restype = ctypes.c_char_p

    # Object operations
    lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    lib.bpf_object__open_file.restype = bpf_object_p

    lib.bpf_object__load.argtypes = [bpf_object_p]
    lib.bpf_object__load.restype = ctypes.c_int

    lib.bpf_object__close.argtypes = [bpf_object_p]
    lib.bpf_object__close.restype = None

    lib.bpf_object__name.argtypes = [bpf_object_p]
    lib.bpf_object__name.restype = ctypes.c_char_p

    # Program iteration and info
    lib.bpf_object__next_program.argtypes = [bpf_object_p, bpf_program_p]
    lib.bpf_object__next_program.restype = bpf_program_p

    lib.bpf_program__name.argtypes = [bpf_program_p]
    lib.bpf_program__name.restype = ctypes.c_char_p

    lib.bpf_program__fd.argtypes = [bpf_program_p]
    lib.bpf_program__fd.restype = ctypes.c_int

    lib.bpf_program__section_name.argtypes = [bpf_program_p]
    lib.bpf_program__section_name.restype = ctypes.c_char_p

    lib.bpf_program__type.argtypes = [bpf_program_p]
    lib.bpf_program__type.restype = ctypes.c_int

    # Program attachment
    lib.bpf_program__attach.argtypes = [bpf_program_p]
    lib.bpf_program__attach.restype = bpf_link_p

    lib.bpf_program__attach_kprobe.argtypes = [bpf_program_p, ctypes.c_bool, ctypes.c_char_p]
    lib.bpf_program__attach_kprobe.restype = bpf_link_p

    lib.bpf_program__attach_tracepoint.argtypes = [bpf_program_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.bpf_program__attach_tracepoint.restype = bpf_link_p

    lib.bpf_program__attach_uprobe.argtypes = [
        bpf_program_p,
        ctypes.c_bool,  # retprobe
        ctypes.c_int,  # pid (-1 for all)
        ctypes.c_char_p,  # binary_path
        ctypes.c_size_t,  # func_offset
    ]
    lib.bpf_program__attach_uprobe.restype = bpf_link_p

    lib.bpf_program__attach_raw_tracepoint.argtypes = [bpf_program_p, ctypes.c_char_p]
    lib.bpf_program__attach_raw_tracepoint.restype = bpf_link_p

    # Link operations
    lib.bpf_link__destroy.argtypes = [bpf_link_p]
    lib.bpf_link__destroy.restype = ctypes.c_int

    lib.bpf_link__fd.argtypes = [bpf_link_p]
    lib.bpf_link__fd.restype = ctypes.c_int

    # Map iteration and info
    lib.bpf_object__next_map.argtypes = [bpf_object_p, bpf_map_p]
    lib.bpf_object__next_map.restype = bpf_map_p

    lib.bpf_map__name.argtypes = [bpf_map_p]
    lib.bpf_map__name.restype = ctypes.c_char_p

    lib.bpf_map__fd.argtypes = [bpf_map_p]
    lib.bpf_map__fd.restype = ctypes.c_int

    lib.bpf_map__type.argtypes = [bpf_map_p]
    lib.bpf_map__type.restype = ctypes.c_int

    lib.bpf_map__key_size.argtypes = [bpf_map_p]
    lib.bpf_map__key_size.restype = ctypes.c_uint

    lib.bpf_map__value_size.argtypes = [bpf_map_p]
    lib.bpf_map__value_size.restype = ctypes.c_uint

    lib.bpf_map__max_entries.argtypes = [bpf_map_p]
    lib.bpf_map__max_entries.restype = ctypes.c_uint

    # Map element operations (these use libbpf syscall wrappers)
    lib.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    lib.bpf_map_lookup_elem.restype = ctypes.c_int

    lib.bpf_map_update_elem.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint64,
    ]
    lib.bpf_map_update_elem.restype = ctypes.c_int

    lib.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
    lib.bpf_map_delete_elem.restype = ctypes.c_int

    lib.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    lib.bpf_map_get_next_key.restype = ctypes.c_int

    # Error handling
    lib.libbpf_strerror.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
    lib.libbpf_strerror.restype = ctypes.c_int

    # libbpf_get_error - returns error code from pointer (for NULL check)
    lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
    lib.libbpf_get_error.restype = ctypes.c_long

    # Ring buffer functions
    lib.ring_buffer__new.argtypes = [
        ctypes.c_int,  # map_fd
        RING_BUFFER_SAMPLE_FN,  # sample_cb
        ctypes.c_void_p,  # ctx
        ctypes.c_void_p,  # opts (NULL)
    ]
    lib.ring_buffer__new.restype = ring_buffer_p

    lib.ring_buffer__poll.argtypes = [ring_buffer_p, ctypes.c_int]
    lib.ring_buffer__poll.restype = ctypes.c_int

    lib.ring_buffer__consume.argtypes = [ring_buffer_p]
    lib.ring_buffer__consume.restype = ctypes.c_int

    lib.ring_buffer__free.argtypes = [ring_buffer_p]
    lib.ring_buffer__free.restype = None

    lib.ring_buffer__add.argtypes = [
        ring_buffer_p,  # rb
        ctypes.c_int,  # map_fd
        RING_BUFFER_SAMPLE_FN,  # sample_cb
        ctypes.c_void_p,  # ctx
    ]
    lib.ring_buffer__add.restype = ctypes.c_int

    lib.ring_buffer__epoll_fd.argtypes = [ring_buffer_p]
    lib.ring_buffer__epoll_fd.restype = ctypes.c_int

    # Perf buffer functions
    lib.perf_buffer__new.argtypes = [
        ctypes.c_int,  # map_fd
        ctypes.c_size_t,  # page_cnt
        PERF_BUFFER_SAMPLE_FN,  # sample_cb
        PERF_BUFFER_LOST_FN,  # lost_cb
        ctypes.c_void_p,  # ctx
        ctypes.c_void_p,  # opts (NULL)
    ]
    lib.perf_buffer__new.restype = perf_buffer_p

    lib.perf_buffer__poll.argtypes = [perf_buffer_p, ctypes.c_int]
    lib.perf_buffer__poll.restype = ctypes.c_int

    lib.perf_buffer__consume.argtypes = [perf_buffer_p]
    lib.perf_buffer__consume.restype = ctypes.c_int

    lib.perf_buffer__free.argtypes = [perf_buffer_p]
    lib.perf_buffer__free.restype = None


def init(libbpf_path: str | Path | None = None) -> None:
    """Initialize libbpf with optional custom library path.

    Call before first use to specify a custom libbpf.so path.
    If not called, bundled library will be loaded on first use.

    Args:
        libbpf_path: Path to libbpf.so. If None, uses bundled library.

    Raises:
        RuntimeError: If already initialized.
        OSError: If library cannot be loaded.
    """
    global _lib, _initialized

    if _initialized:
        raise RuntimeError("tinybpf already initialized. Call init() before any other function.")

    if libbpf_path is not None:
        _lib = ctypes.CDLL(str(libbpf_path))
    else:
        _lib = _load_bundled()

    _setup_function_signatures(_lib)
    _initialized = True


def _load_bundled() -> ctypes.CDLL:
    """Load bundled libbpf.so from package directory."""
    pkg_dir = Path(__file__).parent
    for name in ["libbpf.so.1", "libbpf.so"]:
        path = pkg_dir / name
        if path.exists():
            return ctypes.CDLL(str(path))

    raise OSError(
        "Bundled libbpf.so not found. "
        "Use a wheel with bundled library or call init(libbpf_path='...')."
    )


def _get_lib() -> ctypes.CDLL:
    """Get library handle, initializing if needed."""
    if not _initialized:
        init()
    assert _lib is not None
    return _lib


def libbpf_version() -> str:
    """Return the libbpf library version string."""
    lib = _get_lib()
    version_bytes = lib.libbpf_version_string()
    return version_bytes.decode("utf-8")


def libbpf_strerror(err: int) -> str:
    """Convert libbpf error code to string."""
    lib = _get_lib()
    buf = ctypes.create_string_buffer(256)
    lib.libbpf_strerror(err, buf, len(buf))
    return buf.value.decode("utf-8")
