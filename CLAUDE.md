# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

tinybpf is a minimal Python library for loading and interacting with pre-compiled CO-RE (Compile Once, Run Everywhere) eBPF programs. It uses ctypes bindings to a bundled libbpf shared library, with no runtime dependencies except libelf (typically pre-installed on Linux systems).

## Documentation Structure

| Document | Audience | Purpose |
|----------|----------|---------|
| `README.md` | Library users | API reference, installation, quick start |
| `GUIDE.md` | BPF developers | Patterns for writing BPF programs that work with tinybpf |
| `DEVELOPMENT.md` | Contributors | Dev setup, make targets, CI/CD workflows |
| `examples/` | BPF developers | Runnable programs demonstrating GUIDE.md patterns |
| `llms.txt` | AI assistants | Concise API reference |

**Key principles:**
- README.md stays concise - API reference, not tutorials
- GUIDE.md is the learning path for BPF patterns; references examples/
- DEVELOPMENT.md is strictly for contributors
- examples/ are complete, runnable programs with brief READMEs

## Development

See `DEVELOPMENT.md` for full documentation. Key commands:

```bash
make check     # Run all code quality checks (ruff, mypy)
make test      # Run tests
make compile   # Compile eBPF programs
```

## Architecture

### Key Design Patterns

1. **ctypes over cffi/Cython**: Zero build-time dependencies, pure Python wheels.

2. **Bundled libbpf, system libelf**: System libbpf versions vary too widely (need 1.4.0+), but libelf is stable and ubiquitous.

3. **Generic types**: `BpfMap[KT, VT]`, `BpfRingBuffer[T]` for type-safe key/value/event handling.

4. **Dict-like interfaces**: `BpfMap` supports `[]` access, iteration, `.items()`, `.keys()`, `.values()`.

5. **Context managers**: `BpfObject` and `BpfLink` implement `__enter__`/`__exit__` for resource cleanup.

6. **Error handling**: libbpf returns `-errno` directly. Use `abs(ret)` to extract error codes, not `ctypes.get_errno()`. See `_check_err()` in `_types.py`.

7. **TYPE_CHECKING imports**: Use `if TYPE_CHECKING:` blocks for imports only needed by type hints, avoiding circular imports.

## Testing

- Most tests require root/CAP_BPF and compiled BPF programs in `tests/bpf/`
- Tests use `requires_root` marker to skip when unprivileged
- `test_api.py` and `test_version.py` run without privileges

## Conventions

- **Library code**: Check existing modules in `src/tinybpf/` for patterns
- **Examples**: Check existing examples for structure (PEP 723 headers, signal handling)
- **Tests**: Check `tests/conftest.py` for fixtures and existing tests for patterns

## BPF Development Notes

### Exporting Structs to BTF

Event structs for ring/perf buffers must be explicitly anchored in BTF:

```c
struct event _event_anchor __attribute__((unused));
```

### Inspecting BTF

```bash
bpftool btf dump file path/to/program.bpf.o | grep -A 10 "'mystruct'"
```
