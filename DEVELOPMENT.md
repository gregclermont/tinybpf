# Development Guide

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager
- [gh](https://cli.github.com/) CLI (for workflow triggers)

## Runtime Dependencies

tinybpf bundles a pre-built `libbpf.so` for version consistency, but libbpf requires `libelf` at runtime.

**On most Linux systems**, libelf is already installed (systemd depends on it). You can verify:

```bash
ldconfig -p | grep libelf
```

**If missing** (e.g., minimal containers):

```bash
# Ubuntu/Debian
apt install libelf1

# Fedora/RHEL
dnf install elfutils-libelf

# Alpine
apk add libelf
```

**Why bundle libbpf but not libelf?**
- System libbpf versions vary widely (Ubuntu 22.04 has 0.5.0, we need 1.4.0+)
- libelf is stable, ubiquitous, and has minimal dependencies
- Bundling libelf would also require bundling libzstd, liblzma, libbz2

## Local Development

### macOS

eBPF requires Linux. On macOS, use [Lima](https://lima-vm.io/) to run tests in a VM:

```bash
# One-time setup
make lima-create

# Run tests (auto-detects macOS, uses Lima)
make test
```

### Linux

```bash
# Run tests (auto-detects Linux, runs directly)
make test
```

### Makefile Targets

Commands auto-detect OS and do the right thing:

| Target | Description |
|--------|-------------|
| `make test` | Run tests (Linux: direct, macOS: via Lima) |
| `make setup` | Download libbpf (Linux: direct, macOS: via Lima) |
| `make compile` | Compile eBPF programs (Linux: local Docker, macOS: Docker in Lima) |
| `make clean` | Remove compiled objects |

macOS-only:

| Target | Description |
|--------|-------------|
| `make lima-create` | Create Lima VM with Docker, make, and uv (one-time) |
| `make lima-shell` | Drop into Lima VM shell at project directory |
| `make lima-delete` | Remove Lima VM |

The Lima VM is a full development environment. You can work from macOS (calling into the VM) or shell into it and run everything directly, including Claude Code.

### Running Individual Tests

```bash
# On Linux
uv run pytest tests/test_api.py -v
uv run pytest tests/test_load.py::test_load_minimal -v

# On macOS - drop into Lima shell, then run pytest directly
make lima-shell
uv run pytest tests/test_api.py -v
```

## Code Quality

| Target | Description |
|--------|-------------|
| `make check` | Run all checks (format, lint, typecheck) |
| `make lint` | Run ruff linter |
| `make lint-fix` | Run ruff linter with auto-fix |
| `make format` | Run ruff formatter |
| `make typecheck` | Run mypy type checker |

### Pre-commit Hooks

Pre-commit hooks run the same checks as CI. Install them to catch issues before pushing:

```bash
make setup-hooks
```

This installs a custom hook that uses `uv run` instead of a hardcoded venv path. This ensures hooks work in both macOS and Lima (where the Python binary paths differ).

### Validating Changes

**Always run pre-commit before pushing** to avoid CI failures:

```bash
# Run all checks (same as CI)
uv run pre-commit run --all-files
```

This runs:
- `ruff` - linting and auto-fixes
- `ruff-format` - code formatting
- `mypy` - type checking

**Quick individual checks** (useful during development):

```bash
uv run ruff check src/ tests/     # Lint only
uv run ruff format src/ tests/    # Format only
uv run mypy                       # Type check only
```

## Building

### Build Wheel Locally

```bash
pip install setuptools wheel
pip wheel . --no-build-isolation --wheel-dir dist/
```

### Building eBPF Programs

tinybpf provides a Docker image for compiling eBPF programs. It bundles libbpf headers and pre-generated vmlinux.h for CO-RE support.

**Local development:**

```bash
# Recommended: use make (auto-detects OS)
make compile

# Advanced: run docker directly (on Linux, or inside Lima shell on macOS)
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c -o build/
docker run --rm -v $(pwd):/src -e EXTRA_CFLAGS="-DDEBUG" ghcr.io/gregclermont/tinybpf-compile program.bpf.c
```

**In CI (GitHub Actions):**

```yaml
- name: Build eBPF programs
  run: |
    docker run --rm -v ${{ github.workspace }}:/src \
      ghcr.io/gregclermont/tinybpf-compile \
      src/*.bpf.c
```

**Image tags:**

| Tag | Description |
|-----|-------------|
| `latest` | Latest from main branch |
| `libbpf-X.Y.Z` | Specific libbpf version |

**Supported architectures:** linux/amd64, linux/arm64 (auto-detected)

For CO-RE compatibility, portable BPF patterns, and event struct design, see [GUIDE.md](GUIDE.md).

## CI/CD Workflows

### Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INFRASTRUCTURE                                │
│  (run occasionally when updating toolchain)                         │
│                                                                      │
│  build-libbpf.yml ──────► libbpf-v{version} release (tarballs)      │
│                                  │                                   │
│  build-compile-image.yml ──► ghcr.io/gregclermont/tinybpf-compile   │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         DEVELOPMENT                                  │
│  (run on every push/PR)                                             │
│                                                                      │
│  ci.yml ──► build eBPF test programs ──► run tests                  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          RELEASE                                     │
│  (manual trigger for each release)                                  │
│                                                                      │
│  release.yml ──► build wheels ──► test ──► GitHub release           │
│                                              │                       │
│                                              ▼                       │
│                                    update gh-pages index             │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        VERIFICATION                                  │
│  (manual trigger after release)                                     │
│                                                                      │
│  e2e-test.yml ──► install from index ──► run tests                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Workflow Reference

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR, manual | Fast tests (py3.12), full matrix on dispatch |
| `build-libbpf.yml` | Manual | Build libbpf native libs for new version |
| `build-compile-image.yml` | Push to docker/, manual | Build and publish eBPF compile Docker image |
| `release.yml` | Manual | Full release pipeline with multi-arch testing |
| `e2e-test.yml` | Manual | Verify released package from index |

### Continuous Integration

CI runs automatically on push to `main` and pull requests (Python 3.12, x86_64 only for speed).

**Manual trigger with custom matrix** (for debugging):

```bash
# Test all Python versions
gh workflow run ci.yml -f python-versions='["3.10", "3.11", "3.12"]'

# Test specific version on aarch64
gh workflow run ci.yml -f arch=aarch64

# Watch the run
gh run watch
```

**Flow:**
1. `build-ebpf` job runs `make compile` to build eBPF test programs
2. `test` job downloads libbpf, eBPF objects, and runs pytest

### Building libbpf

Run this when updating to a new libbpf version:

```bash
# Build libbpf binaries for both architectures
gh workflow run build-libbpf.yml -f libbpf_version=1.5.0

# Watch progress
gh run watch

# After successful build, update the version file
echo "1.5.0" > .libbpf-version
git add .libbpf-version
git commit -m "Update libbpf to 1.5.0"
git push
```

| | |
|---|---|
| **Trigger** | Manual only |
| **Input** | `libbpf_version` (e.g., "1.5.0") |
| **Produces** | GitHub release `libbpf-v{version}` with `libbpf-x86_64.tar.gz` and `libbpf-aarch64.tar.gz` |

### Building the Compile Image

| | |
|---|---|
| **Trigger** | Push to `docker/`, `.libbpf-version`, or manual |
| **Input** | `push` (boolean, default: true) |
| **Produces** | `ghcr.io/gregclermont/tinybpf-compile` with tags: `latest`, `libbpf-{version}`, `{sha}` |

```bash
gh workflow run build-compile-image.yml
```

### Creating a Release

The version is read from `src/tinybpf/__init__.py`. To release:

```bash
# 1. Update __version__ in src/tinybpf/__init__.py, commit, and push
# 2. Trigger release workflow (reads version from repo)
gh workflow run release.yml

# Watch progress (builds wheels, tests on all Python versions + both archs, creates release)
gh run watch

# After success, verify the release
gh release view v0.2.0
```

| | |
|---|---|
| **Trigger** | Manual only |
| **Input** | None (version read from `__init__.py`) |
| **Produces** | GitHub release `v{version}` with wheels, updated gh-pages index |

**Flow:**
1. **prepare**: Read version from `__init__.py`, validate format, check release doesn't exist
2. **build** (x86_64 + aarch64): Download libbpf, build platform-specific wheels
3. **test-wheel** (x86_64 + aarch64): Test wheels on Python 3.10-3.12
4. **release**: Create GitHub release with wheel assets
5. **update-index**: Update `gh-pages` branch with pip-compatible index

### End-to-End Testing

Verify a released version installs correctly from the package index:

```bash
# Test default (Python 3.12)
gh workflow run e2e-test.yml -f version=0.2.0

# Test all Python versions
gh workflow run e2e-test.yml -f version=0.2.0 -f python-versions='["3.10", "3.11", "3.12"]'

# Watch
gh run watch
```

| | |
|---|---|
| **Trigger** | Manual only |
| **Inputs** | `version` (required), `python-versions` (optional) |
| **Produces** | Test results |

### Reusable Workflows

These are called by other workflows and should not be triggered directly.

| Workflow | Called by | Purpose |
|----------|-----------|---------|
| `_test-source.yml` | ci.yml | Test source code with pytest |
| `_test-wheel.yml` | release.yml | Test built wheel before release |
| `_test-install.yml` | e2e-test.yml | Test installing from package index |

### Common Sequences

**Regular development:**

```bash
# Automatic on push/PR
git push  # → triggers ci.yml
```

**Creating a release:**

```bash
# 1. Update version in __init__.py, commit, and push
vim src/tinybpf/__init__.py  # update __version__
git add src/tinybpf/__init__.py && git commit -m "Bump version to 0.2.0" && git push

# 2. Run release workflow (reads version from repo)
gh workflow run release.yml
gh run watch  # wait for completion

# 3. Verify the release
gh workflow run e2e-test.yml -f version=0.2.0
gh run watch
```

**Updating libbpf version:**

```bash
# 1. Build new libbpf binaries
gh workflow run build-libbpf.yml -f libbpf_version=1.5.0
gh run watch

# 2. Update version file (triggers Docker image rebuild)
echo "1.5.0" > .libbpf-version
git add .libbpf-version
git commit -m "Update libbpf to 1.5.0"
git push

# 3. Verify CI still passes
gh run watch
```

**Updating the eBPF compile image:**

```bash
# Edit docker/Dockerfile or docker/entrypoint.sh
git add docker/
git commit -m "Update eBPF compile image"
git push  # → triggers build-compile-image.yml
```

## Useful Commands

```bash
# List recent workflow runs
gh run list

# View specific run details
gh run view <run-id>

# Download artifacts from a run
gh run download <run-id>

# List releases
gh release list

# View release assets
gh release view v0.2.0

# Install from custom index (for testing)
pip install tinybpf==0.2.0 --index-url https://gregclermont.github.io/tinybpf/
```
