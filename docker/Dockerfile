# eBPF CO-RE compilation image
# Build: docker build --build-arg LIBBPF_VERSION=1.4.0 --build-arg VMLINUX_VERSION=6.18 -t ghcr.io/gregclermont/tinybpf-compile docker/
# Usage: docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile program.bpf.c
# Versions are read from src/tinybpf/.libbpf-version and src/tinybpf/.vmlinux-version by CI

FROM debian:bookworm-slim

ARG LIBBPF_VERSION
ARG VMLINUX_VERSION

# Install clang and minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download libbpf headers into bpf/ subdirectory for #include <bpf/...> to work
RUN mkdir -p /opt/libbpf/bpf && \
    curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar xz -C /opt/libbpf/bpf --strip-components=2 "libbpf-${LIBBPF_VERSION}/src"

# Download vmlinux.h for x86_64 and aarch64
RUN mkdir -p /opt/vmlinux/x86_64 /opt/vmlinux/aarch64 && \
    curl -sL "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/x86/vmlinux_${VMLINUX_VERSION}.h" \
        -o /opt/vmlinux/x86_64/vmlinux.h && \
    curl -sL "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/aarch64/vmlinux_${VMLINUX_VERSION}.h" \
        -o /opt/vmlinux/aarch64/vmlinux.h

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /src
ENTRYPOINT ["/entrypoint.sh"]
