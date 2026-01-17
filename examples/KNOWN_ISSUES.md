# Known Issues and Notes

This document captures issues and observations encountered while developing the tinybpf examples.

## Environment Issues

### 1. Container Without BPF Support

**Issue:** The development environment (kernel 4.4.0 in a container) does not support the BPF syscall.

**Error:**
```
libbpf: Error in bpf_object__probe_loading():Function not implemented(38).
Couldn't load trivial BPF program. Make sure your kernel supports BPF (CONFIG_BPF_SYSCALL=y)
```

**Impact:** Cannot actually load or test BPF programs in this environment. The examples compile correctly but cannot be executed.

**Workaround:** The examples were designed and compiled but not runtime-tested. They should work on a proper Linux system with kernel 5.8+ and BPF support.

### 2. Docker Not Available

**Issue:** Docker was not available in the development environment for using the recommended compilation image.

**Workaround:** Used locally installed clang-18 and libbpf-dev for compilation.

### 3. Missing vmlinux.h

**Issue:** No pre-generated vmlinux.h was available, and the kernel BTF was not available (`/sys/kernel/btf/vmlinux` missing).

**Workaround:** Created a minimal vmlinux.h (`examples/bpf/vmlinux.h`) with essential kernel type definitions needed for the examples. This works for compilation but may need adjustment for CO-RE compatibility with different kernel versions.

## API/Library Issues

### 1. Bundled libbpf Not Found in Dev Install

**Issue:** When installing tinybpf in editable mode (`pip install -e .`), the bundled libbpf.so is not available.

**Error:**
```
OSError: Bundled libbpf.so not found. Use a wheel with bundled library or call init(libbpf_path='...').
```

**Workaround:** Use `bindings.init(libbpf_path='/usr/lib/x86_64-linux-gnu/libbpf.so')` to initialize with system libbpf.

**Suggestion for tinybpf:** Consider auto-falling back to system libbpf if bundled is not found, or provide clearer documentation for development setups.

### 2. Type Registration Before Map Access

**Observation:** The `register_type()` method must be called on the BpfObject before accessing maps if you want BTF validation of ctypes structures.

**Not an issue**, just worth documenting in examples.

## BPF Program Issues

### 1. vmlinux.h Structure Ordering

**Issue:** Structures in vmlinux.h must be defined before they are used as fields in other structures.

**Example:** `struct sock_common` uses `struct in6_addr`, which must be defined first.

**Fix:** Carefully order structure definitions or use forward declarations where appropriate.

### 2. CO-RE Field Access Syntax

**Issue:** BPF_CORE_READ requires specific nested structure syntax: `BPF_CORE_READ(sk, __sk_common.skc_family)` not `BPF_CORE_READ(sk, skc_family)`.

**Impact:** The minimal vmlinux.h needed to include the nested `__sk_common` structure with proper field names.

### 3. BPF_KPROBE/BPF_KRETPROBE Macros

**Issue:** The BPF_KPROBE macros from bpf_tracing.h require `__VMLINUX_H__` to be defined for proper pt_regs handling, but defining it before including our custom vmlinux.h breaks the basic type definitions.

**Workaround:** Used traditional `struct pt_regs *ctx` function signatures with `PT_REGS_PARM1()` and `PT_REGS_RC()` macros.

### 4. BPF Map Type Constants

**Issue:** `BPF_MAP_TYPE_RINGBUF`, `BPF_MAP_TYPE_HASH`, etc., and `BPF_ANY`, `BPF_NOEXIST` constants are not defined in the system bpf_helpers.h.

**Workaround:** Added `enum bpf_map_type` and flag definitions to the custom vmlinux.h.

## Testing Limitations

Since the BPF programs could not be loaded in the development environment, the following are **NOT verified**:

1. Runtime behavior of the BPF programs
2. Correct event structure alignment and field offsets
3. Ring buffer polling and event delivery
4. kprobe/kretprobe attachment to actual kernel functions
5. XDP attachment and packet processing
6. CO-RE relocation with actual kernel BTF

**Recommendation:** Test these examples on a proper Linux system with:
- Kernel 5.8+ (for ring buffers)
- CAP_BPF or root privileges
- CONFIG_BPF_SYSCALL=y
- CONFIG_DEBUG_INFO_BTF=y (for CO-RE)

## Potential Improvements to tinybpf

1. **Auto-fallback to system libbpf:** When bundled library isn't found, try system libbpf automatically.

2. **Better error messages:** The "Function not implemented" error could include a note about checking BPF syscall support.

3. **Documentation for development setup:** Add section on using system libbpf for development.

4. **Example vmlinux.h:** Consider bundling a minimal vmlinux.h for examples, or documenting how to obtain one.

5. **Async support documentation:** The async iteration (`async for event in rb`) is mentioned but not well documented.

## Notes for Production Use

1. The minimal vmlinux.h is sufficient for compilation but may not provide full CO-RE compatibility. For production, generate vmlinux.h from your target kernel's BTF or use the Docker compilation image.

2. The examples use relatively large ring buffers (1MB). Adjust based on expected event rates.

3. Per-CPU arrays are used for high-frequency counters to avoid lock contention.

4. The network tracker's CO-RE access patterns assume standard kernel sock structure layout. Test on target kernels.

5. XDP programs should be tested with different network drivers as XDP support varies.
