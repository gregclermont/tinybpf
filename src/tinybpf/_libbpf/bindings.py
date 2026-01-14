"""ctypes bindings for libbpf."""

import ctypes
from pathlib import Path

_lib: ctypes.CDLL | None = None
_initialized: bool = False


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

    _lib.libbpf_version_string.restype = ctypes.c_char_p
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
