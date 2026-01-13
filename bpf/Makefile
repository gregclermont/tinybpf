# BPF program compilation Makefile
# This compiles test BPF programs for use with tinybpf

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Clang flags for BPF compilation
BPF_CFLAGS := -g -O2 -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I.

# Find all .bpf.c files
BPF_SRCS := $(wildcard *.bpf.c)
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

.PHONY: all clean vmlinux

all: $(BPF_OBJS)

# Generate vmlinux.h from running kernel BTF (optional, for full CO-RE support)
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile BPF programs
%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@ 2>/dev/null || true

clean:
	rm -f *.bpf.o

# Help target
help:
	@echo "BPF Program Compilation"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Compile all BPF programs (default)"
	@echo "  vmlinux  - Generate vmlinux.h from kernel BTF"
	@echo "  clean    - Remove compiled objects"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang with BPF target support"
	@echo "  - llvm-strip (optional, for stripping debug info)"
	@echo "  - bpftool (optional, for generating vmlinux.h)"
