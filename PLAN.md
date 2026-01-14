# tinybpf

## Goal
Python package for communicating with CO-RE eBPF programs

## Constraints
- Installable via `uv add` / `uv --with` / inline script deps
- Wheel must bundle libbpf (required to load eBPF)

## Minimal Package
- Load libbpf.so via ctypes
- Call `libbpf_version_string()` → proves .so loads and works
- No root/BPF/kernel needed for this test

## Distribution
- Wheel = complete package (Python code + bundled libbpf.so)
- One wheel per arch in GitHub Release
- User picks URL for their arch:
  - `uv add https://github.com/.../releases/download/dev/tinybpf-...-x86_64.whl`
  - `uv add https://github.com/.../releases/download/dev/tinybpf-...-aarch64.whl`
- Rolling `dev` tag: force-updated on each push

## Build & CI
- libbpf.so: build from https://github.com/libbpf/libbpf (`make` in `src/`)

### Workflows
1. **build-libbpf** (manual trigger)
   - Build libbpf in manylinux container (per arch)
   - Upload to `libbpf-v1.x.x` release (permanent, no expiry)

2. **ci** (on any push)
   - **build** job (if src/** or pyproject.toml changed):
     - Matrix: [x86_64, aarch64]
     - Download libbpf from `libbpf-v1.x.x` release (per arch)
     - Build wheel → one per arch (manylinux_2_28_*)
     - Upload all to `dev` release
   - **test** job (always, needs build if it ran):
     - `astral-sh/setup-uv@v4`
     - `uv pip install <wheel-url> && uv run pytest`
