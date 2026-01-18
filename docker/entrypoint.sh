#!/bin/bash
set -e

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        TARGET_ARCH="x86"
        VMLINUX_DIR="/opt/vmlinux/x86_64"
        ;;
    aarch64)
        TARGET_ARCH="arm64"
        VMLINUX_DIR="/opt/vmlinux/aarch64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

LIBBPF_HEADERS="/opt/libbpf"

# Allow custom vmlinux.h via VMLINUX env var
if [ -n "$VMLINUX" ]; then
    if [ ! -f "$VMLINUX" ]; then
        echo "Error: VMLINUX file not found: $VMLINUX" >&2
        exit 1
    fi
    VMLINUX_INCLUDE="-include $VMLINUX"
else
    VMLINUX_INCLUDE="-I$VMLINUX_DIR"
fi

# Build CFLAGS
CFLAGS="-g -O2 -target bpf"
CFLAGS="$CFLAGS -D__TARGET_ARCH_${TARGET_ARCH}"
CFLAGS="$CFLAGS -I$LIBBPF_HEADERS"
CFLAGS="$CFLAGS $VMLINUX_INCLUDE"

# Allow extra CFLAGS via environment
if [ -n "$EXTRA_CFLAGS" ]; then
    CFLAGS="$CFLAGS $EXTRA_CFLAGS"
fi

if [ $# -eq 0 ]; then
    echo "Usage: docker run --rm -v \$(pwd):/src ghcr.io/gregclermont/tinybpf-compile [OPTIONS] <source.bpf.c ...>"
    echo ""
    echo "Compiles eBPF source files (.bpf.c) to object files (.bpf.o)"
    echo ""
    echo "Options:"
    echo "  -o DIR    Output directory (default: same as source)"
    echo ""
    echo "Environment:"
    echo "  VMLINUX         Path to custom vmlinux.h (default: bundled kernel 6.18)"
    echo "  EXTRA_CFLAGS    Additional compiler flags"
    echo ""
    echo "Examples:"
    echo "  docker run --rm -v \$(pwd):/src ghcr.io/gregclermont/tinybpf-compile program.bpf.c"
    echo "  docker run --rm -v \$(pwd):/src ghcr.io/gregclermont/tinybpf-compile -o build/ src/*.bpf.c"
    echo ""
    echo "  # Use custom vmlinux.h for older kernel:"
    echo "  docker run --rm -v \$(pwd):/src -v /path/to/vmlinux.h:/vmlinux.h -e VMLINUX=/vmlinux.h \\"
    echo "    ghcr.io/gregclermont/tinybpf-compile program.bpf.c"
    exit 0
fi

# Parse options
OUTPUT_DIR=""
while getopts "o:" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        *) exit 1 ;;
    esac
done
shift $((OPTIND - 1))

# Create output directory if specified
if [ -n "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
fi

# Compile each source file
FAILED=0
for src in "$@"; do
    if [ ! -f "$src" ]; then
        echo "Error: File not found: $src" >&2
        FAILED=1
        continue
    fi

    # Determine output path
    if [ -n "$OUTPUT_DIR" ]; then
        obj="$OUTPUT_DIR/$(basename "${src%.bpf.c}.bpf.o")"
    else
        obj="${src%.bpf.c}.bpf.o"
    fi

    echo "Compiling: $src -> $obj"
    if ! clang $CFLAGS -c "$src" -o "$obj"; then
        echo "Error: Failed to compile $src" >&2
        FAILED=1
    fi
done

exit $FAILED
