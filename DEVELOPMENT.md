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

tinybpf provides a Docker image for compiling eBPF programs. It bundles libbpf headers and pre-generated vmlinux.h for CO-RE support.

**Local development:**

```bash
# Compile a single file
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile program.bpf.c

# Compile multiple files
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c

# Output to specific directory
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile -o build/ src/*.bpf.c

# With extra compiler flags
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
| `build-compile-image.yml` | Push to docker/, manual | Build and publish eBPF compile Docker image |
| `release.yml` | Manual | Full release pipeline with multi-arch testing |
| `e2e-test.yml` | Manual | Verify released package from index |

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
