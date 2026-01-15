# CI/CD Workflows

This document describes the GitHub Actions workflows used in this project.

## Overview

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

## Infrastructure Workflows

### build-libbpf.yml

Builds pre-compiled libbpf shared libraries for multiple architectures.

| | |
|---|---|
| **Trigger** | Manual only |
| **Input** | `libbpf_version` (e.g., "1.5.0") |
| **Produces** | GitHub release `libbpf-v{version}` with `libbpf-x86_64.tar.gz` and `libbpf-aarch64.tar.gz` |

**When to run:** When upgrading to a new libbpf version.

```bash
# Build libbpf 1.5.0
gh workflow run build-libbpf.yml -f libbpf_version=1.5.0

# After success, update version file
echo "1.5.0" > .libbpf-version
git add .libbpf-version && git commit -m "Update libbpf to 1.5.0" && git push
```

### build-compile-image.yml

Builds the Docker image used to compile eBPF programs.

| | |
|---|---|
| **Trigger** | Push to `docker/`, `.libbpf-version`, or manual |
| **Input** | `push` (boolean, default: true) |
| **Produces** | `ghcr.io/gregclermont/tinybpf-compile` with tags: `latest`, `libbpf-{version}`, `{sha}` |

**When to run:** Automatically runs when `docker/` directory changes. Manual trigger if needed.

```bash
gh workflow run build-compile-image.yml
```

## Development Workflow

### ci.yml

Main CI workflow that builds eBPF test programs and runs the test suite.

| | |
|---|---|
| **Trigger** | Push to main, pull requests, or manual |
| **Inputs** | `python-versions` (JSON array), `arch` (x86_64/aarch64) |
| **Produces** | Test results, `test-ebpf-objects` artifact |

**Flow:**
1. `build-ebpf` job runs `make compile` to build eBPF test programs
2. `test` job downloads libbpf, eBPF objects, and runs pytest

```bash
# Run with all Python versions
gh workflow run ci.yml -f python-versions='["3.9", "3.10", "3.11", "3.12"]'

# Run on ARM
gh workflow run ci.yml -f arch=aarch64
```

## Release Workflow

### release.yml

Complete release pipeline: build wheels, test, publish, update index.

| | |
|---|---|
| **Trigger** | Manual only |
| **Input** | `version` (required, e.g., "0.2.0") |
| **Produces** | GitHub release `v{version}` with wheels, updated gh-pages index |

**Flow:**
1. **build** (x86_64 + aarch64): Download libbpf, build platform-specific wheels
2. **test-wheel** (x86_64 + aarch64): Test wheels on Python 3.9-3.12
3. **release**: Create GitHub release with wheel assets
4. **update-index**: Update `gh-pages` branch with pip-compatible index

```bash
gh workflow run release.yml -f version=0.2.0
```

## Verification Workflow

### e2e-test.yml

Tests installing a released version from the package index.

| | |
|---|---|
| **Trigger** | Manual only |
| **Inputs** | `version` (required), `python-versions` (optional) |
| **Produces** | Test results |

**When to run:** After a release to verify the published package works.

```bash
gh workflow run e2e-test.yml -f version=0.2.0
```

## Reusable Workflows

These are called by other workflows and should not be triggered directly.

| Workflow | Called by | Purpose |
|----------|-----------|---------|
| `_test-source.yml` | ci.yml | Test source code with pytest |
| `_test-wheel.yml` | release.yml | Test built wheel before release |
| `_test-install.yml` | e2e-test.yml | Test installing from package index |

## Common Sequences

### Regular Development

```bash
# Automatic on push/PR
git push  # → triggers ci.yml
```

### Creating a Release

```bash
# 1. Run release workflow
gh workflow run release.yml -f version=0.2.0
gh run watch  # wait for completion

# 2. Verify the release
gh workflow run e2e-test.yml -f version=0.2.0
gh run watch
```

### Updating libbpf Version

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

### Updating the eBPF Compile Image

```bash
# Edit docker/Dockerfile or docker/entrypoint.sh
git add docker/
git commit -m "Update eBPF compile image"
git push  # → triggers build-compile-image.yml
```
