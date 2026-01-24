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
    echo "  -o PATH   Output directory, or file path when compiling a single file"
    echo ""
    echo "Environment:"
    echo "  VMLINUX         Path to custom vmlinux.h (default: bundled kernel 6.18)"
    echo "  EXTRA_CFLAGS    Additional compiler flags"
    echo ""
    echo "Examples:"
    echo "  docker run --rm -v \$(pwd):/src ghcr.io/gregclermont/tinybpf-compile program.bpf.c"
    echo "  docker run --rm -v \$(pwd):/src ghcr.io/gregclermont/tinybpf-compile src/*.bpf.c -o build/"
    echo ""
    echo "  # Use custom vmlinux.h for older kernel:"
    echo "  docker run --rm -v \$(pwd):/src -v /path/to/vmlinux.h:/vmlinux.h -e VMLINUX=/vmlinux.h \\"
    echo "    ghcr.io/gregclermont/tinybpf-compile program.bpf.c"
    exit 0
fi

# Parse arguments (options can appear anywhere)
OUTPUT_DIR=""
SOURCES=()
while [ $# -gt 0 ]; do
    case "$1" in
        -o)
            if [ -z "$2" ]; then
                echo "Error: -o requires an argument" >&2
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            SOURCES+=("$1")
            shift
            ;;
    esac
done

# Determine if output is a file or directory
OUTPUT_FILE=""
OUTPUT_DIR_RESOLVED=""
if [ -n "$OUTPUT_DIR" ]; then
    if [[ "$OUTPUT_DIR" == */ ]]; then
        # Trailing slash = directory
        OUTPUT_DIR_RESOLVED="$OUTPUT_DIR"
        mkdir -p "$OUTPUT_DIR_RESOLVED"
    elif [[ "$OUTPUT_DIR" == *.bpf.o ]]; then
        # .bpf.o suffix = file
        if [ ${#SOURCES[@]} -gt 1 ]; then
            echo "Error: Cannot use output file path with multiple sources" >&2
            exit 1
        fi
        OUTPUT_FILE="$OUTPUT_DIR"
        mkdir -p "$(dirname "$OUTPUT_FILE")"
    elif [ -d "$OUTPUT_DIR" ]; then
        # Existing directory
        OUTPUT_DIR_RESOLVED="$OUTPUT_DIR"
    elif [ -f "$OUTPUT_DIR" ]; then
        # Existing file
        if [ ${#SOURCES[@]} -gt 1 ]; then
            echo "Error: Cannot use output file path with multiple sources" >&2
            exit 1
        fi
        OUTPUT_FILE="$OUTPUT_DIR"
    else
        # Ambiguous - doesn't exist, no trailing slash, no .bpf.o suffix
        echo "Error: Output path '$OUTPUT_DIR' is ambiguous (does not exist)" >&2
        echo "Use trailing / for directory (e.g., build/) or .bpf.o suffix for file" >&2
        exit 1
    fi
fi

# Compile each source file
FAILED=0
for src in "${SOURCES[@]}"; do
    if [ ! -f "$src" ]; then
        echo "Error: File not found: $src" >&2
        FAILED=1
        continue
    fi

    # Determine output path
    if [ -n "$OUTPUT_FILE" ]; then
        obj="$OUTPUT_FILE"
    elif [ -n "$OUTPUT_DIR_RESOLVED" ]; then
        obj="$OUTPUT_DIR_RESOLVED/$(basename "${src%.bpf.c}.bpf.o")"
    else
        obj="${src%.bpf.c}.bpf.o"
    fi

    echo "Compiling: $src -> $obj"
    # shellcheck disable=SC2086  # CFLAGS must be word-split
    if ! clang $CFLAGS -c "$src" -o "$obj"; then
        echo "Error: Failed to compile $src" >&2
        FAILED=1
    fi
done

exit $FAILED
