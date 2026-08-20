"""Part 01 CLI tests: T-01-01, T-01-11, T-01-12, T-01-13."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from caudit import __version__
from caudit.cli import main as cli_main
from caudit.cli.main import COMMAND_EXIT_CODES, main
from caudit.status import ExitCode


def test_version_matches_package_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    """T-01-01: --version prints the package version and exits 0."""
    code = main(["--version"])
    captured = capsys.readouterr()
    assert code == ExitCode.OK
    assert __version__ in captured.out


def test_every_exit_code_is_reachable_from_a_command() -> None:
    """T-01-11: every ExitCode member is referenced by at least one CLI path."""
    declared = set().union(*COMMAND_EXIT_CODES.values())
    assert declared == set(ExitCode), (
        "COMMAND_EXIT_CODES must cover every ExitCode member; missing "
        f"{sorted(set(ExitCode) - declared)}"
    )

    # The mapping must not be able to lie: each code it claims has to appear
    # by name somewhere in the CLI package.
    cli_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(Path(cli_main.__file__).parent.glob("*.py"))
    )
    for code in declared:
        assert re.search(rf"ExitCode\.{code.name}\b", cli_source), (
            f"ExitCode.{code.name} is declared in COMMAND_EXIT_CODES but never used"
        )

    # And the mapping must not go quiet: a command added without an entry
    # would leave the table describing a CLI that no longer exists.
    registered = {
        (command.name or command.callback.__name__)
        for command in cli_main.app.registered_commands
        if command.callback is not None
    }
    assert registered <= set(COMMAND_EXIT_CODES), (
        "every command needs an entry in COMMAND_EXIT_CODES; missing "
        f"{sorted(registered - set(COMMAND_EXIT_CODES))}"
    )


def test_scan_without_compile_commands_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-01-12: the missing required flag is named, exit 2."""
    code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == ExitCode.USAGE
    assert "--compile-commands" in captured.err
    # The spec's posture: never guess build flags, say how to make a real one.
    assert "CMAKE_EXPORT_COMPILE_COMMANDS" in captured.err


def test_scan_runs_the_whole_pipeline_and_writes_the_three_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], no_analyzers: None
) -> None:
    """AC-01-8, now with parts 05-08 behind it: intake to report, no LLM.

    The fixture holds the no-analyzer branch still, so the exit code is 3
    rather than 0 for exactly one reason — a run that could not look must not
    report the status a clean run reports — and the artifacts are written
    anyway, saying so in words.
    """
    from tests.conftest import compdb_entry, write_compdb, write_tree

    root = write_tree(tmp_path, {"src/a.c": "int main(void){return 0;}\n"})
    database = write_compdb(root, [compdb_entry(root, str(root / "src/a.c"))])
    out = tmp_path / "report-out"

    code = main(["scan", str(root), "--compile-commands", str(database), "--out", str(out)])
    captured = capsys.readouterr()
    assert code == ExitCode.ENVIRONMENT
    assert "Scan plan" in captured.out
    assert "translation units selected" in captured.out
    assert "No analyzer ran" in captured.out
    for name in ("report.md", "results.sarif", "run-manifest.json"):
        assert (out / name).is_file(), f"{name} was not written"


def test_unexpected_exception_produces_a_trace_id_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-01-13: exit 4, a trace id on stderr, no raw traceback for the user."""

    def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated failure inside a command")

    monkeypatch.setattr("caudit.cli.main.ToolchainProbe", explode)
    code = main(["doctor"])
    captured = capsys.readouterr()
    assert code == ExitCode.INTERNAL
    assert re.search(r"Trace id: [0-9a-f]{12}", captured.err)
    assert "Traceback (most recent call last)" not in captured.err
    assert "simulated failure" not in captured.err


def test_unknown_log_level_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--log-level", "chatty", "doctor"])
    assert code == ExitCode.USAGE
    assert "chatty" in capsys.readouterr().err


def test_bad_set_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--set", "llvm_version", "doctor"])
    assert code == ExitCode.USAGE
    assert "KEY=VALUE" in capsys.readouterr().err
