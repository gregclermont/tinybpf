"""Command-line interface for tinybpf."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from tinybpf import __version__


def _get_version_file(filename: str) -> str | None:
    """Read a version file from the package directory."""
    pkg_file = Path(__file__).parent / filename
    if pkg_file.exists():
        return pkg_file.read_text().strip()
    return None


def cmd_version(_args: argparse.Namespace) -> int:
    """Show version information."""
    print(f"tinybpf {__version__}")

    libbpf_version = _get_version_file(".libbpf-version")
    if libbpf_version:
        print(f"libbpf {libbpf_version}")

    vmlinux_version = _get_version_file(".vmlinux-version")
    if vmlinux_version:
        print(f"vmlinux.h kernel {vmlinux_version} (Docker image default)")

    return 0


def cmd_docker_compile(args: argparse.Namespace) -> int:
    """Compile BPF programs using the Docker image."""
    if not shutil.which("docker"):
        print("Error: docker not found in PATH", file=sys.stderr)
        return 1

    libbpf_version = _get_version_file(".libbpf-version")
    if libbpf_version:
        image_tag = f"ghcr.io/gregclermont/tinybpf-compile:libbpf-{libbpf_version}"
    else:
        image_tag = "ghcr.io/gregclermont/tinybpf-compile:latest"

    # Build docker command
    cwd = Path.cwd()
    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{cwd}:/src",
        image_tag,
        *args.sources,
    ]

    # Pass through output directory if specified
    if args.output:
        docker_cmd.extend(["-o", args.output])

    if args.verbose:
        print(f"Running: {' '.join(docker_cmd)}", file=sys.stderr)

    return subprocess.call(docker_cmd)


def cmd_run_elevated(args: argparse.Namespace) -> int:
    """Run a Python script with elevated privileges."""
    script = args.script
    script_args = args.script_args

    if not Path(script).exists():
        print(f"Error: script not found: {script}", file=sys.stderr)
        return 1

    # Find the Python executable
    python_exe = sys.executable

    # Build the command with sudo
    cmd = ["sudo", python_exe, script, *script_args]

    if args.verbose:
        print(f"Running: {' '.join(cmd)}", file=sys.stderr)

    return subprocess.call(cmd)


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="tinybpf",
        description="tinybpf command-line tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    version_parser.set_defaults(func=cmd_version)

    # docker-compile command
    compile_parser = subparsers.add_parser(
        "docker-compile",
        help="Compile BPF programs using Docker",
        description="Compile .bpf.c files using the tinybpf-compile Docker image.",
    )
    compile_parser.add_argument(
        "-o",
        "--output",
        help="Output directory for compiled .bpf.o files",
    )
    compile_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print the docker command being executed",
    )
    compile_parser.add_argument(
        "sources",
        nargs="+",
        help="Source .bpf.c files to compile",
    )
    compile_parser.set_defaults(func=cmd_docker_compile)

    # run-elevated command
    run_parser = subparsers.add_parser(
        "run-elevated",
        help="Run a Python script with sudo",
        description="Run a Python script with elevated privileges using sudo.",
    )
    run_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print the command being executed",
    )
    run_parser.add_argument(
        "script",
        help="Python script to run",
    )
    run_parser.add_argument(
        "script_args",
        nargs="*",
        help="Arguments to pass to the script",
    )
    run_parser.set_defaults(func=cmd_run_elevated)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
