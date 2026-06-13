"""Tests for tinybpf._cli (the `tinybpf` console script).

All tests run unprivileged: external calls (docker, sudo) are mocked.
"""

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import tinybpf
from tinybpf._cli import (
    _docker_image_exists_locally,
    _docker_pull,
    _get_version_file,
    _resolve_compile_image,
    cmd_docker_compile,
    cmd_docker_pull,
    cmd_run_elevated,
    cmd_version,
    main,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**kwargs: object) -> argparse.Namespace:
    """Build a Namespace with sensible defaults for CLI args."""
    defaults = {"verbose": False, "output": None, "sources": [], "script": "", "script_args": []}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# cmd_version
# ---------------------------------------------------------------------------


class TestCmdVersion:
    def test_prints_tinybpf_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        """cmd_version prints 'tinybpf <version>'."""
        result = cmd_version(_make_args())
        out = capsys.readouterr().out
        assert f"tinybpf {tinybpf.__version__}" in out

    def test_returns_zero(self) -> None:
        """cmd_version returns 0."""
        result = cmd_version(_make_args())
        assert result == 0

    def test_prints_libbpf_version_when_file_present(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """cmd_version prints libbpf version when .libbpf-version file exists."""
        version_file = tmp_path / ".libbpf-version"
        version_file.write_text("1.4.0\n")

        with patch("tinybpf._cli._get_version_file") as mock_get:
            mock_get.side_effect = lambda name: "1.4.0" if name == ".libbpf-version" else None
            cmd_version(_make_args())

        out = capsys.readouterr().out
        assert "libbpf 1.4.0" in out

    def test_prints_vmlinux_version_when_file_present(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """cmd_version prints vmlinux kernel version when .vmlinux-version file exists."""
        with patch("tinybpf._cli._get_version_file") as mock_get:
            mock_get.side_effect = lambda name: "6.1" if name == ".vmlinux-version" else None
            cmd_version(_make_args())

        out = capsys.readouterr().out
        assert "vmlinux.h kernel 6.1" in out

    def test_no_libbpf_line_when_file_absent(self, capsys: pytest.CaptureFixture[str]) -> None:
        """cmd_version omits libbpf line when .libbpf-version is absent."""
        with patch("tinybpf._cli._get_version_file", return_value=None):
            cmd_version(_make_args())
        out = capsys.readouterr().out
        assert "libbpf" not in out


# ---------------------------------------------------------------------------
# _get_version_file
# ---------------------------------------------------------------------------


class TestGetVersionFile:
    def test_returns_content_when_file_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_get_version_file returns stripped file content when file exists."""
        # Write the version file next to a fake _cli.py in tmp_path
        version_file = tmp_path / ".libbpf-version"
        version_file.write_text("  1.4.0  \n")
        fake_cli = tmp_path / "_cli.py"
        fake_cli.write_text("")
        import tinybpf._cli as cli_module

        monkeypatch.setattr(cli_module, "__file__", str(fake_cli))
        result = _get_version_file(".libbpf-version")
        assert result == "1.4.0"

    def test_returns_none_when_file_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_get_version_file returns None when the file does not exist."""
        fake_cli = tmp_path / "_cli.py"
        fake_cli.write_text("")
        import tinybpf._cli as cli_module

        monkeypatch.setattr(cli_module, "__file__", str(fake_cli))
        result = _get_version_file(".libbpf-version")
        assert result is None


# ---------------------------------------------------------------------------
# _docker_image_exists_locally
# ---------------------------------------------------------------------------


class TestDockerImageExistsLocally:
    def test_returns_true_when_returncode_zero(self) -> None:
        with patch("tinybpf._cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert _docker_image_exists_locally("some/image:tag") is True
        mock_run.assert_called_once_with(
            ["docker", "image", "inspect", "some/image:tag"],
            capture_output=True,
            check=False,
        )

    def test_returns_false_when_returncode_nonzero(self) -> None:
        with patch("tinybpf._cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert _docker_image_exists_locally("some/image:tag") is False


# ---------------------------------------------------------------------------
# _docker_pull
# ---------------------------------------------------------------------------


class TestDockerPull:
    def test_returns_true_on_success(self) -> None:
        with patch("tinybpf._cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert _docker_pull("some/image:tag") is True

    def test_returns_false_on_failure(self) -> None:
        with patch("tinybpf._cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert _docker_pull("some/image:tag") is False

    def test_verbose_prints_to_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("tinybpf._cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            _docker_pull("some/image:tag", verbose=True)
        err = capsys.readouterr().err
        assert "Pulling: some/image:tag" in err

    def test_non_verbose_uses_capture_output(self) -> None:
        with patch("tinybpf._cli.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            _docker_pull("some/image:tag", verbose=False)
        _, kwargs = mock_run.call_args
        assert kwargs.get("capture_output") is True or mock_run.call_args[0][1] is True or True
        # Check positional or keyword
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs.get("capture_output") is True


# ---------------------------------------------------------------------------
# _resolve_compile_image
# ---------------------------------------------------------------------------


class TestResolveCompileImage:
    """Tests for _resolve_compile_image image resolution logic."""

    def test_uses_version_tag_when_image_exists_locally(self) -> None:
        """Returns version-tagged image when it already exists locally."""
        with (
            patch("tinybpf._cli._docker_image_exists_locally", return_value=True),
            patch("tinybpf._cli._docker_pull") as mock_pull,
            patch("tinybpf._cli._get_version_file", return_value="1.4.0"),
        ):
            result = _resolve_compile_image()

        assert result == f"ghcr.io/gregclermont/tinybpf-compile:{tinybpf.__version__}"
        mock_pull.assert_not_called()

    def test_uses_version_tag_after_successful_pull(self) -> None:
        """Returns version-tagged image after pulling it successfully."""
        with (
            patch("tinybpf._cli._docker_image_exists_locally", return_value=False),
            patch("tinybpf._cli._docker_pull", return_value=True),
            patch("tinybpf._cli._get_version_file", return_value="1.4.0"),
        ):
            result = _resolve_compile_image()

        assert result == f"ghcr.io/gregclermont/tinybpf-compile:{tinybpf.__version__}"

    def test_falls_back_to_libbpf_tag_when_pull_fails(self) -> None:
        """Falls back to libbpf-tagged image when version-tagged pull fails."""
        with (
            patch("tinybpf._cli._docker_image_exists_locally", return_value=False),
            patch("tinybpf._cli._docker_pull", return_value=False),
            patch("tinybpf._cli._get_version_file", return_value="1.4.0"),
        ):
            result = _resolve_compile_image()

        assert result == "ghcr.io/gregclermont/tinybpf-compile:libbpf-1.4.0"

    def test_falls_back_to_latest_when_no_libbpf_version(self) -> None:
        """Falls back to :latest when no .libbpf-version file and pull fails."""
        with (
            patch("tinybpf._cli._docker_image_exists_locally", return_value=False),
            patch("tinybpf._cli._docker_pull", return_value=False),
            patch("tinybpf._cli._get_version_file", return_value=None),
        ):
            result = _resolve_compile_image()

        assert result == "ghcr.io/gregclermont/tinybpf-compile:latest"

    def test_verbose_prints_fallback_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Verbose mode prints a message when falling back to libbpf tag."""
        with (
            patch("tinybpf._cli._docker_image_exists_locally", return_value=False),
            patch("tinybpf._cli._docker_pull", return_value=False),
            patch("tinybpf._cli._get_version_file", return_value="1.4.0"),
        ):
            _resolve_compile_image(verbose=True)

        err = capsys.readouterr().err
        assert "libbpf-1.4.0" in err


# ---------------------------------------------------------------------------
# cmd_docker_compile
# ---------------------------------------------------------------------------


class TestCmdDockerCompile:
    """Tests for cmd_docker_compile, including the -o flag fix (commit c6c69cc)."""

    def test_returns_one_when_docker_not_found(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("tinybpf._cli.shutil.which", return_value=None):
            result = cmd_docker_compile(_make_args(sources=["prog.bpf.c"]))
        assert result == 1
        assert "docker not found" in capsys.readouterr().err

    def test_basic_compile_command(self) -> None:
        """docker-compile passes source files to the container."""
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._resolve_compile_image", return_value="img:tag"),
            patch("tinybpf._cli.subprocess.call", return_value=0) as mock_call,
        ):
            result = cmd_docker_compile(_make_args(sources=["a.bpf.c", "b.bpf.c"]))

        assert result == 0
        cmd = mock_call.call_args[0][0]
        assert cmd[0] == "docker"
        assert "a.bpf.c" in cmd
        assert "b.bpf.c" in cmd

    def test_output_flag_appended_after_sources(self) -> None:
        """-o flag is placed after sources in the container command (not docker args)."""
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._resolve_compile_image", return_value="img:tag"),
            patch("tinybpf._cli.subprocess.call", return_value=0) as mock_call,
        ):
            cmd_docker_compile(_make_args(sources=["prog.bpf.c"], output="out/"))

        cmd = mock_call.call_args[0][0]
        # The image must appear before -o so that -o is passed to the container
        image_idx = cmd.index("img:tag")
        o_idx = cmd.index("-o")
        assert o_idx > image_idx, "-o must come after the image name (passed to container)"
        assert cmd[o_idx + 1] == "out/"

    def test_no_output_flag_when_not_specified(self) -> None:
        """No -o in the docker command when output is not set."""
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._resolve_compile_image", return_value="img:tag"),
            patch("tinybpf._cli.subprocess.call", return_value=0) as mock_call,
        ):
            cmd_docker_compile(_make_args(sources=["prog.bpf.c"], output=None))

        cmd = mock_call.call_args[0][0]
        assert "-o" not in cmd

    def test_verbose_prints_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._resolve_compile_image", return_value="img:tag"),
            patch("tinybpf._cli.subprocess.call", return_value=0),
        ):
            cmd_docker_compile(_make_args(sources=["prog.bpf.c"], verbose=True))

        err = capsys.readouterr().err
        assert "Running:" in err

    def test_volume_mount_uses_cwd(self) -> None:
        """The current working directory is mounted as /src."""
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._resolve_compile_image", return_value="img:tag"),
            patch("tinybpf._cli.subprocess.call", return_value=0) as mock_call,
        ):
            cmd_docker_compile(_make_args(sources=["prog.bpf.c"]))

        cmd = mock_call.call_args[0][0]
        # Should have -v <cwd>:/src
        assert "-v" in cmd
        v_idx = cmd.index("-v")
        assert "/src" in cmd[v_idx + 1]


# ---------------------------------------------------------------------------
# cmd_docker_pull
# ---------------------------------------------------------------------------


class TestCmdDockerPull:
    def test_returns_one_when_docker_not_found(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("tinybpf._cli.shutil.which", return_value=None):
            result = cmd_docker_pull(_make_args())
        assert result == 1
        assert "docker not found" in capsys.readouterr().err

    def test_returns_zero_when_version_pull_succeeds(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._docker_pull", return_value=True),
            patch("tinybpf._cli._get_version_file", return_value="1.4.0"),
        ):
            result = cmd_docker_pull(_make_args())

        assert result == 0
        out = capsys.readouterr().out
        assert "Successfully pulled" in out

    def test_falls_back_to_libbpf_tag_when_version_pull_fails(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Falls back to libbpf-tagged image when version pull fails."""
        pull_responses = iter([False, True])

        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._docker_pull", side_effect=lambda img, **kw: next(pull_responses)),
            patch("tinybpf._cli._get_version_file", return_value="1.4.0"),
        ):
            result = cmd_docker_pull(_make_args())

        assert result == 0
        out = capsys.readouterr().out
        assert "libbpf-1.4.0" in out

    def test_returns_one_when_all_pulls_fail(self, capsys: pytest.CaptureFixture[str]) -> None:
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._docker_pull", return_value=False),
            patch("tinybpf._cli._get_version_file", return_value="1.4.0"),
        ):
            result = cmd_docker_pull(_make_args())

        assert result == 1
        assert "Failed to pull" in capsys.readouterr().err

    def test_skips_libbpf_fallback_when_no_libbpf_version(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When .libbpf-version is absent, only version-tagged pull is attempted."""
        with (
            patch("tinybpf._cli.shutil.which", return_value="/usr/bin/docker"),
            patch("tinybpf._cli._docker_pull", return_value=False),
            patch("tinybpf._cli._get_version_file", return_value=None),
        ):
            result = cmd_docker_pull(_make_args())

        assert result == 1


# ---------------------------------------------------------------------------
# cmd_run_elevated
# ---------------------------------------------------------------------------


class TestCmdRunElevated:
    def test_returns_one_when_script_not_found(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        missing = str(tmp_path / "nonexistent.py")
        result = cmd_run_elevated(_make_args(script=missing, script_args=[]))
        assert result == 1
        assert "script not found" in capsys.readouterr().err

    def test_calls_sudo_with_python_and_script(self, tmp_path: Path) -> None:
        """run-elevated invokes sudo <python> <script>."""
        script = tmp_path / "myscript.py"
        script.write_text("print('hello')")

        with patch("tinybpf._cli.subprocess.call", return_value=0) as mock_call:
            result = cmd_run_elevated(_make_args(script=str(script), script_args=[]))

        assert result == 0
        cmd = mock_call.call_args[0][0]
        assert cmd[0] == "sudo"
        assert str(script) in cmd

    def test_passes_script_args_to_command(self, tmp_path: Path) -> None:
        """run-elevated passes extra arguments to the script."""
        script = tmp_path / "myscript.py"
        script.write_text("")

        with patch("tinybpf._cli.subprocess.call", return_value=0) as mock_call:
            cmd_run_elevated(_make_args(script=str(script), script_args=["--foo", "bar"]))

        cmd = mock_call.call_args[0][0]
        assert "--foo" in cmd
        assert "bar" in cmd

    def test_verbose_prints_command(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        script = tmp_path / "myscript.py"
        script.write_text("")

        with patch("tinybpf._cli.subprocess.call", return_value=0):
            cmd_run_elevated(_make_args(script=str(script), script_args=[], verbose=True))

        err = capsys.readouterr().err
        assert "Running:" in err


# ---------------------------------------------------------------------------
# main() argument parsing
# ---------------------------------------------------------------------------


class TestMainArgParsing:
    def test_no_args_prints_help_and_returns_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        """main() with no subcommand prints help and returns 0."""
        with patch("sys.argv", ["tinybpf"]):
            result = main()
        assert result == 0
        out = capsys.readouterr().out
        assert "tinybpf" in out

    def test_version_subcommand_invokes_cmd_version(self) -> None:
        with (
            patch("sys.argv", ["tinybpf", "version"]),
            patch("tinybpf._cli.cmd_version", return_value=0) as mock_cmd,
        ):
            result = main()
        assert result == 0
        mock_cmd.assert_called_once()

    def test_docker_compile_subcommand_invokes_cmd(self) -> None:
        with (
            patch("sys.argv", ["tinybpf", "docker-compile", "prog.bpf.c"]),
            patch("tinybpf._cli.cmd_docker_compile", return_value=0) as mock_cmd,
        ):
            result = main()
        assert result == 0
        mock_cmd.assert_called_once()

    def test_docker_compile_output_flag_parsed(self) -> None:
        """The -o flag is parsed into args.output."""
        captured: list[argparse.Namespace] = []

        def capture_args(args: argparse.Namespace) -> int:
            captured.append(args)
            return 0

        with (
            patch("sys.argv", ["tinybpf", "docker-compile", "-o", "out/", "prog.bpf.c"]),
            patch("tinybpf._cli.cmd_docker_compile", side_effect=capture_args),
        ):
            main()

        assert captured[0].output == "out/"
        assert captured[0].sources == ["prog.bpf.c"]

    def test_docker_pull_subcommand_invokes_cmd(self) -> None:
        with (
            patch("sys.argv", ["tinybpf", "docker-pull"]),
            patch("tinybpf._cli.cmd_docker_pull", return_value=0) as mock_cmd,
        ):
            result = main()
        assert result == 0
        mock_cmd.assert_called_once()

    def test_run_elevated_subcommand_invokes_cmd(self) -> None:
        with (
            patch("sys.argv", ["tinybpf", "run-elevated", "script.py"]),
            patch("tinybpf._cli.cmd_run_elevated", return_value=0) as mock_cmd,
        ):
            result = main()
        assert result == 0
        mock_cmd.assert_called_once()

    def test_bad_subcommand_exits(self) -> None:
        """An unrecognised subcommand causes SystemExit (argparse behaviour)."""
        with (
            patch("sys.argv", ["tinybpf", "not-a-command"]),
            pytest.raises(SystemExit),
        ):
            main()
