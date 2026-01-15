# tinybpf

Minimal Python library for loading and interacting with pre-compiled CO-RE eBPF programs.

- Pure Python (ctypes bindings to bundled libbpf)
- No build dependencies, no runtime dependencies except libelf
- Dict-like map access, context managers for cleanup

## Install

```bash
uv add tinybpf --extra-index-url https://gregclermont.github.io/tinybpf/
```

<details>
<summary>pip</summary>

```bash
pip install tinybpf --extra-index-url https://gregclermont.github.io/tinybpf/
```
</details>

Wheels available for `manylinux_2_28_x86_64` and `manylinux_2_28_aarch64`.

## Usage

```python
import tinybpf

with tinybpf.load("program.bpf.o") as obj:
    # Attach a program
    link = obj.program("trace_exec").attach_kprobe("do_execve")

    # Read from a map
    for key, value in obj.maps["events"].items():
        print(key, value)
```

## API

### Loading

- `tinybpf.load(path)` - Load a `.bpf.o` file, returns `BpfObject`

### BpfObject

- `obj.programs` - Dict-like access to programs by name
- `obj.maps` - Dict-like access to maps by name
- `obj.program(name)` / `obj.map(name)` - Get by name
- Context manager support (`with` statement)

### BpfProgram

Attach methods:
- `attach()` - Auto-attach based on section name
- `attach_kprobe(func_name, retprobe=False)`
- `attach_kretprobe(func_name)`
- `attach_tracepoint(category, name)`
- `attach_raw_tracepoint(name)`
- `attach_uprobe(binary_path, offset=0, pid=-1, retprobe=False)`
- `attach_uretprobe(binary_path, offset=0, pid=-1)`

Properties: `name`, `section`, `type`, `fd`, `info`

### BpfMap

Dict-like interface:
- `map[key]`, `map[key] = value`, `del map[key]`
- `key in map`, `for key in map`
- `map.keys()`, `map.values()`, `map.items()`
- `map.lookup(key)`, `map.update(key, value, flags)`, `map.delete(key)`

Keys/values: `bytes`, `int`, or `ctypes.Structure`

Properties: `name`, `type`, `key_size`, `value_size`, `max_entries`, `fd`, `info`

### BpfLink

- `link.destroy()` - Detach the program
- `link.fd` - File descriptor
- Context manager support

### Other

- `tinybpf.version()` - Package version
- `tinybpf.libbpf_version()` - Bundled libbpf version
- `BpfError` - Exception type with `errno` attribute

## Requirements

- Linux with kernel 5.8+ (for CO-RE support)
- libelf (typically pre-installed)
- Root or `CAP_BPF` capability

## Building on tinybpf

### Compiling eBPF programs

Use the `ghcr.io/gregclermont/tinybpf-compile` Docker image to compile `.bpf.c` files:

```bash
docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c
```

Output files are written alongside the sources. Use `-o build/` to specify an output directory.

The image includes libbpf headers and `vmlinux.h` for x86_64 and aarch64. It auto-detects the target architecture.

### CI workflow

Example GitHub Actions workflow to compile and test:

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Compile eBPF programs
        run: |
          docker run --rm -v ${{ github.workspace }}:/src \
            ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c -o build/

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install tinybpf --extra-index-url https://gregclermont.github.io/tinybpf/
          pip install pytest

      - name: Run tests
        run: sudo pytest tests/ -v
```

### Local development on macOS

Since eBPF requires Linux, use [Lima](https://lima-vm.io/) to run a Linux VM:

```bash
# Create and start an Ubuntu VM
limactl create --name=ebpf template:ubuntu-24.04
limactl start ebpf

# Run commands in the VM
limactl shell ebpf -- sudo pytest /path/to/your/tests -v
```

You'll need to configure mounts for your project directory. See this project's [Makefile](Makefile) for a complete setup with `lima-create`, `lima-shell`, and automatic mount configuration.
