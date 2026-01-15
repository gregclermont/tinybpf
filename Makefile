# Development Makefile
#
# Commands auto-detect OS:
#   make setup    # Download libbpf (Linux: direct, macOS: via Lima)
#   make test     # Run tests (Linux: direct, macOS: via Lima)
#   make compile  # Compile eBPF (Docker, works anywhere)
#
# macOS-only:
#   make lima-create   # One-time VM setup
#   make lima-delete   # Remove VM

UNAME := $(shell uname)
LIMA_VM ?= tinybpf
PROJECT_DIR := $(shell pwd)
ARCH := $(shell uname -m)

# Compile eBPF programs using Docker (works on any OS)
compile:
	docker run --rm -v $(PROJECT_DIR):/src ghcr.io/gregclermont/tinybpf-compile tests/bpf/*.bpf.c

#
# Linux targets (run directly on Linux)
#
setup-linux:
	@test -f $(PROJECT_DIR)/src/tinybpf/_libbpf/libbpf.so.1 || \
		(echo "Downloading libbpf..." && \
		mkdir -p src/tinybpf/_libbpf && \
		curl -sL https://github.com/gregclermont/tinybpf/releases/download/libbpf-v$$(cat .libbpf-version)/libbpf-$(ARCH).tar.gz | \
		tar xz -C src/tinybpf/_libbpf/)

test-linux: compile setup-linux
	uv run --with pytest pytest tests/ -v

#
# macOS/Lima targets (run Linux targets inside Lima VM)
#
lima-create:
	limactl create --name=$(LIMA_VM) --tty=false template:ubuntu-24.04
	@echo "Configuring mount for $(PROJECT_DIR)..."
	@sed -i '' 's|- location: "~"|  - location: "$(PROJECT_DIR)"\n    writable: true|' ~/.lima/$(LIMA_VM)/lima.yaml
	limactl start $(LIMA_VM)
	@echo "Installing uv..."
	limactl shell $(LIMA_VM) -- bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
	@echo "Lima VM '$(LIMA_VM)' ready. Run 'make test' to test."

lima-delete:
	limactl delete -f $(LIMA_VM)

setup-lima:
	@limactl shell $(LIMA_VM) -- which make > /dev/null || \
		(echo "Installing make..." && limactl shell $(LIMA_VM) -- sudo apt-get update -qq && limactl shell $(LIMA_VM) -- sudo apt-get install -qq -y make)
	limactl shell $(LIMA_VM) -- make -C $(PROJECT_DIR) setup-linux

test-lima: compile setup-lima
	limactl shell $(LIMA_VM) -- bash -c 'sudo $$HOME/.local/bin/uv run --project $(PROJECT_DIR) --with pytest pytest $(PROJECT_DIR)/tests -v'

#
# Auto-detect OS and dispatch to appropriate target
#
ifeq ($(UNAME),Darwin)
setup: setup-lima
test: test-lima
else
setup: setup-linux
test: test-linux
endif

# Clean compiled objects
clean:
	rm -f tests/bpf/*.bpf.o

.PHONY: compile setup-linux test-linux lima-create lima-delete setup-lima test-lima setup test clean
