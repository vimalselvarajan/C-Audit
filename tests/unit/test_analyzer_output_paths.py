"""Part 07 regression: the raw-output directory reaches analyzers as an absolute path.

Every analyzer runs with ``cwd=unit.directory`` — the *scanned project's* build
directory, which is not ours — and two of them are handed a path to write to:
``clang-tidy --export-fixes`` and the static analyzer's ``-o``. A relative
``out_dir`` therefore resolves against a directory that does not contain it, and
the output goes nowhere.

The two failures are not equally loud, and that asymmetry is the reason this
needs its own test rather than a line in an existing one:

* clang-tidy calls it an error and exits non-zero, so the run is recorded as
  failed, a limitation names the unit, and the report is marked partial. Bad,
  but visible from the summary table.
* the static analyzer calls it ``warning: could not create file`` and exits
  **0**. caudit sees a completed run that produced no results, records no
  reason, and the candidates stage is not degraded by it. The report is clean
  and the diagnostics are gone — the outcome CLAUDE.md names as the worst
  available.

``caudit scan --out caudit-report``, the documented default, is relative, so
this emptied the static analyzer on every default invocation. It survived
because every test that exercised the pass passed an absolute ``tmp_path``, and
because ``stub_subprocess`` ignores the ``cwd`` it is given, so no stubbed run
could reproduce it. This test asserts the property at the boundary instead: what
lands in the argv must not depend on where the callee happens to stand.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from caudit.analyzers.runner import CommandResult, RunStatus
from caudit.analyzers.service import generate_candidates
from caudit.config.loader import Config
from caudit.index import Index
from caudit.intake.plan import Coverage, ScanPlan
from tests.conftest import make_translation_unit

#: The arguments whose value is a path the analyzer subprocess has to create.
#: ``-o`` is the static analyzer's SARIF destination; ``--export-fixes`` is
#: clang-tidy's. Both are the failure this module exists for.
OUTPUT_FLAGS = ("-o", "--export-fixes")


def _recording_runner(seen: list[list[str]]) -> object:
    """A subprocess runner that records argv and starts nothing."""

    def run(command: Sequence[str], _cwd: Path | None, _timeout: float) -> CommandResult:
        seen.append(list(command))
        if "--version" in command:
            return CommandResult(RunStatus.OK, 0, "clang version 18.1.8", 0.0)
        return CommandResult(RunStatus.OK, 0, "", 0.0)

    return run


def _output_arguments(command: Sequence[str]) -> list[str]:
    """Every path this argv tells a tool to write to."""
    values: list[str] = []
    for position, argument in enumerate(command):
        for flag in OUTPUT_FLAGS:
            if argument == flag and position + 1 < len(command):
                values.append(command[position + 1])
            elif argument.startswith(f"{flag}="):
                values.append(argument.split("=", 1)[1])
    return values


@pytest.fixture
def commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Run the pass with a *relative* ``out_dir``, from an unrelated cwd."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text("void a(void)\n{\n    return;\n}\n", encoding="utf-8")
    plan = ScanPlan(
        repo_root=root,
        revision="test",
        compile_commands_path=root / "compile_commands.json",
        units=[make_translation_unit(root, "src/a.c")],
        coverage=Coverage(
            tus_in_database=1,
            tus_selected=1,
            source_files_in_tree=1,
            source_files_covered=1,
            coverage_ratio=1.0,
        ),
    )

    # The caller's cwd is a third place, distinct from both the repository and
    # the output directory. That is the real shape: a user runs `caudit scan
    # ../their-project` from wherever they happen to be.
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    seen: list[list[str]] = []
    generate_candidates(
        plan,
        Index(revision="test", repo_root=root, libclang="stub"),
        Config(),
        out_dir=Path("caudit-report/analyzer-output"),  # relative, as the CLI default is
        subprocess_runner=_recording_runner(seen),  # type: ignore[arg-type]
    )
    return seen


def test_every_output_path_handed_to_an_analyzer_is_absolute(
    commands: list[list[str]],
) -> None:
    """The regression proper: a relative out_dir must not reach the argv."""
    relative = [
        (value, command[0])
        for command in commands
        for value in _output_arguments(command)
        if not Path(value).is_absolute()
    ]
    assert not relative, (
        "these analyzers were told to write to a path relative to a working "
        f"directory they do not share: {relative}"
    )


def test_the_output_paths_land_under_the_directory_that_was_asked_for(
    commands: list[list[str]], tmp_path: Path
) -> None:
    """Absolute is necessary but not sufficient — it has to be the right place.

    Resolving against the caller's cwd is the correct reading of a relative
    ``--out``: the user means "here", not "inside the project I am scanning".
    """
    expected = tmp_path / "cwd" / "caudit-report" / "analyzer-output"
    written = [value for command in commands for value in _output_arguments(command)]
    assert written, "no analyzer was given an output path at all"
    for value in written:
        assert Path(value).parent == expected, f"{value} is not under {expected}"


def test_both_writing_analyzers_are_covered(commands: list[list[str]]) -> None:
    """Guards the test itself: it is worthless if neither flag ever appeared.

    If the profile stops passing one of these, this test would keep passing
    while covering half of what it claims to.
    """
    flags = {
        flag
        for command in commands
        for flag in OUTPUT_FLAGS
        for argument in command
        if argument == flag or argument.startswith(f"{flag}=")
    }
    assert flags == set(OUTPUT_FLAGS), f"only {flags} appeared; expected {set(OUTPUT_FLAGS)}"
