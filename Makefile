# Development Makefile
#
# Commands auto-detect OS:
#   make setup    # Download libbpf (Linux: direct, macOS: via Lima)
#   make test     # Run tests (Linux: direct, macOS: via Lima)
#   make compile  # Compile eBPF (Linux: local Docker, macOS: Docker in Lima)
#
# macOS-only:
#   make lima-create   # One-time VM setup (Ubuntu + Docker)
#   make lima-shell    # Shell into VM at project dir
#   make lima-delete   # Remove VM

UNAME := $(shell uname)
LIMA_VM ?= tinybpf
PROJECT_DIR := $(shell pwd)
ARCH := $(shell uname -m)
# Use separate venv in Lima VM to avoid conflicts with macOS host
LIMA_VENV := /tmp/tinybpf-venv

#
# Linux targets (run directly on Linux)
#
compile-linux:
	docker run --rm -v $(PROJECT_DIR):/src ghcr.io/gregclermont/tinybpf-compile tests/bpf/*.bpf.c examples/*/*.bpf.c

setup-linux:
	@test -f $(PROJECT_DIR)/src/tinybpf/_libbpf/libbpf.so.1 || \
		(echo "Downloading libbpf..." && \
		mkdir -p src/tinybpf/_libbpf && \
		curl -sL https://github.com/gregclermont/tinybpf/releases/download/libbpf-v$$(cat .libbpf-version)/libbpf-$(ARCH).tar.gz | \
		tar xz -C src/tinybpf/_libbpf/)

test-linux: compile setup-linux
	uv run --with pytest --with pytest-asyncio pytest tests/ -v

#
# macOS/Lima targets (run Linux targets inside Lima VM)
#
lima-create:
	limactl create --name=$(LIMA_VM) --tty=false template:docker
	@echo "Configuring mount for $(PROJECT_DIR)..."
	@sed -i '' 's|- location: "~"|  - location: "$(PROJECT_DIR)"\n    writable: true|' ~/.lima/$(LIMA_VM)/lima.yaml
	limactl start $(LIMA_VM)
	@echo "Installing make..."
	limactl shell $(LIMA_VM) -- sudo apt-get update -qq
	limactl shell $(LIMA_VM) -- sudo apt-get install -qq -y make
	@echo "Installing uv..."
	limactl shell $(LIMA_VM) -- bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
	@echo "Configuring uv to use separate venv for interactive shells..."
	limactl shell $(LIMA_VM) -- bash -c 'grep -q UV_PROJECT_ENVIRONMENT ~/.bashrc 2>/dev/null || echo "export UV_PROJECT_ENVIRONMENT=$(LIMA_VENV)" >> ~/.bashrc'
	@echo "Lima VM '$(LIMA_VM)' ready. Run 'make test' to test."

lima-delete:
	limactl delete -f $(LIMA_VM)

lima-shell:
	limactl shell --workdir $(PROJECT_DIR) $(LIMA_VM)

compile-lima:
	limactl shell $(LIMA_VM) -- make -C $(PROJECT_DIR) compile-linux

setup-lima:
	limactl shell $(LIMA_VM) -- make -C $(PROJECT_DIR) setup-linux

test-lima: compile setup-lima
	limactl shell $(LIMA_VM) -- bash -c 'sudo UV_PROJECT_ENVIRONMENT=$(LIMA_VENV) $$HOME/.local/bin/uv run --project $(PROJECT_DIR) --with pytest --with pytest-asyncio pytest $(PROJECT_DIR)/tests -v'

#
# Auto-detect OS and dispatch to appropriate target
#
ifeq ($(UNAME),Darwin)
compile: compile-lima
setup: setup-lima
test: test-lima
else
compile: compile-linux
setup: setup-linux
test: test-linux
endif

# Install git hooks (uses uv, avoids venv path issues)
setup-hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

# Clean compiled objects
clean:
	rm -f tests/bpf/*.bpf.o examples/*/*.bpf.o

#
# Linting and type checking (no OS dispatch needed)
#
lint:
	uv run ruff check src/ tests/

lint-fix:
	uv run ruff check --fix src/ tests/

format:
	uv run ruff format src/ tests/

format-check:
	uv run ruff format --check src/ tests/

typecheck:
	uv run mypy

check: format-check lint typecheck

.PHONY: compile compile-linux compile-lima setup-linux test-linux lima-create lima-delete lima-shell setup-lima test-lima setup test setup-hooks clean lint lint-fix format format-check typecheck check
