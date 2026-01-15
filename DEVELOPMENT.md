# Development Guide

## Prerequisites

- Python 3.9+
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

### Run tests locally

```bash
# Download libbpf for your platform (x86_64)
gh release download libbpf-v$(cat .libbpf-version) --pattern "libbpf-x86_64.tar.gz"
mkdir -p src/tinybpf/_libbpf
tar xzf libbpf-x86_64.tar.gz -C src/tinybpf/_libbpf/

# Run tests
uv run pytest tests/ -v
```

### Build wheel locally

```bash
pip install setuptools wheel
pip wheel . --no-build-isolation --wheel-dir dist/
```

## CI/CD Workflows

### Continuous Integration

CI runs automatically on push to `main` and pull requests (Python 3.12, x86_64 only for speed).

**Manual trigger with custom matrix** (for debugging):

```bash
# Test all Python versions
gh workflow run ci.yml -f python-versions='["3.9", "3.10", "3.11", "3.12"]'

# Test specific version on aarch64
gh workflow run ci.yml -f python-versions='["3.12"]' -f arch=aarch64

# Watch the run
gh run watch
```

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

### Building eBPF Programs

tinybpf provides a reusable GitHub Action for compiling eBPF programs. It downloads libbpf headers matching the bundled version and pre-generated vmlinux.h for CO-RE support.

**In this repo** (CI builds test programs automatically):

```bash
# Test programs are in tests/bpf/*.bpf.c
# CI compiles them before running tests
```

**In your own repo:**

```yaml
- uses: gregclermont/tinybpf/.github/actions/build-ebpf@main
  with:
    sources: 'src/**/*.bpf.c'
    libbpf-version: '1.4.0'  # Must match your tinybpf version
```

**Action inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `sources` | `**/*.bpf.c` | Glob pattern for source files |
| `output-dir` | (same as source) | Output directory for .bpf.o files |
| `libbpf-version` | from `.libbpf-version` | libbpf version for headers |
| `vmlinux-h` | (downloads pre-generated) | Custom vmlinux.h path |
| `arch` | (auto-detect) | Target: x86_64 or aarch64 |
| `extra-cflags` | | Additional clang flags |

**Action outputs:**

| Output | Description |
|--------|-------------|
| `object-files` | Space-separated list of compiled .bpf.o files |
| `libbpf-headers-path` | Path to downloaded libbpf headers |
| `vmlinux-h-path` | Path to vmlinux.h used |

### Creating a Release

```bash
# Trigger release workflow (builds, tests, publishes)
gh workflow run release.yml -f version=0.2.0

# Watch progress (builds wheels, tests on all Python versions + both archs, creates release)
gh run watch

# After success, verify the release
gh release view v0.2.0
```

The release workflow:
1. Builds wheels for x86_64 and aarch64
2. Tests wheels on Python 3.9-3.12 (both architectures via native runners)
3. Creates GitHub release with wheel assets
4. Updates package index on gh-pages

### End-to-End Testing

Verify a released version installs correctly from the package index:

```bash
# Test default (Python 3.12)
gh workflow run e2e-test.yml -f version=0.2.0

# Test all Python versions
gh workflow run e2e-test.yml -f version=0.2.0 -f python-versions='["3.9", "3.10", "3.11", "3.12"]'

# Watch
gh run watch
```

## Workflow Reference

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR, manual | Fast tests (py3.12), full matrix on dispatch |
| `build-libbpf.yml` | Manual | Build libbpf native libs for new version |
| `release.yml` | Manual | Full release pipeline with multi-arch testing |
| `e2e-test.yml` | Manual | Verify released package from index |

| Action | Purpose |
|--------|---------|
| `actions/build-ebpf` | Compile eBPF programs with matching libbpf headers |

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
