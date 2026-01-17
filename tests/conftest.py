"""Shared fixtures and configuration for tinybpf tests.

Fixtures:
- minimal_bpf_path: Path to minimal.bpf.o (tracepoint only)
- test_maps_bpf_path: Path to test_maps.bpf.o (hash, array, percpu maps)
- ringbuf_bpf_path: Path to test_ringbuf.bpf.o (ring buffer maps)
- perf_bpf_path: Path to test_perf.bpf.o (perf event array)
- xdp_bpf_path: Path to test_xdp.bpf.o (XDP program)

All integration tests require root privileges (CAP_BPF, CAP_SYS_ADMIN).
"""

import os
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
BPF_DIR = TESTS_DIR / "bpf"

# Marker for tests requiring root - applied via pytestmark in test files
requires_root = pytest.mark.skipif(
    os.geteuid() != 0, reason="Root privileges required for BPF operations"
)


@pytest.fixture
def minimal_bpf_path() -> Path:
    """Path to compiled minimal.bpf.o test program.

    Contains:
    - trace_openat: tracepoint on syscalls:sys_enter_openat
    """
    path = BPF_DIR / "minimal.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path


@pytest.fixture
def test_maps_bpf_path() -> Path:
    """Path to compiled test_maps.bpf.o test program.

    Contains maps:
    - pid_counts: BPF_MAP_TYPE_HASH (key: u32, value: u64, max: 1024)
    - counters: BPF_MAP_TYPE_ARRAY (key: u32, value: u64, max: 16)
    - percpu_stats: BPF_MAP_TYPE_PERCPU_ARRAY (key: u32, value: u64, max: 4)

    Contains programs:
    - trace_openat: tracepoint
    - trace_tcp_connect: kprobe
    """
    path = BPF_DIR / "test_maps.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path


@pytest.fixture
def ringbuf_bpf_path() -> Path:
    """Path to compiled test_ringbuf.bpf.o test program.

    Contains maps:
    - events: BPF_MAP_TYPE_RINGBUF (256KB)
    - events2: BPF_MAP_TYPE_RINGBUF (256KB)

    Event structure: 24 bytes (pid: u32, tid: u32, comm: char[16])

    Contains programs:
    - trace_execve: tracepoint, emits to events map
    - trace_getpid: tracepoint, emits to events2 map
    """
    path = BPF_DIR / "test_ringbuf.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path


@pytest.fixture
def perf_bpf_path() -> Path:
    """Path to compiled test_perf.bpf.o test program.

    Contains maps:
    - events: BPF_MAP_TYPE_PERF_EVENT_ARRAY

    Event structure: 24 bytes (pid: u32, cpu: u32, comm: char[16])

    Contains programs:
    - trace_getpid: tracepoint, outputs perf events with CPU context
    """
    path = BPF_DIR / "test_perf.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path


@pytest.fixture
def xdp_bpf_path() -> Path:
    """Path to compiled test_xdp.bpf.o test program.

    Contains programs:
    - xdp_pass: XDP program that passes all packets
    """
    path = BPF_DIR / "test_xdp.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path


@pytest.fixture
def core_fail_bpf_path() -> Path:
    """Path to compiled test_core_fail.bpf.o test program.

    This program intentionally fails to load due to CO-RE relocation mismatch.
    It references __data_loc_parent_comm which doesn't exist on kernels that
    use inline arrays for tracepoint comm fields.

    Used to test that libbpf error output is captured in BpfError.
    """
    path = BPF_DIR / "test_core_fail.bpf.o"
    if not path.exists():
        pytest.skip(f"Compiled BPF program not found: {path}")
    return path
