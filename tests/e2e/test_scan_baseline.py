"""Part 08 end-to-end tests: T-08-17 (AC-08-1, AC-08-7), plus the offline path.

T-08-17 needs a real Clang and is deselected by default. The tests above it
drive the same command with analyzers whose subprocess layer is stubbed, so
the whole route — intake, index, candidates, evidence gate, three artifacts,
exit code — is exercised on a machine with no LLVM installed, which includes
this one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft4Validator

from caudit.application.schema_export import SCHEMA_DIR
from caudit.cli.main import main
from caudit.model.manifest import RunManifest
from caudit.status import ExitCode
from tests.conftest import demo_project


def _artifacts(out: Path) -> tuple[str, dict[str, object], RunManifest]:
    report = (out / "report.md").read_text(encoding="utf-8")
    sarif: dict[str, object] = json.loads((out / "results.sarif").read_text(encoding="utf-8"))
    manifest = RunManifest.model_validate_json((out / "run-manifest.json").read_text("utf-8"))
    return report, sarif, manifest


def _run(root: Path, database: Path, out: Path, *extra: str) -> int:
    return main(["scan", str(root), "--compile-commands", str(database), "--out", str(out), *extra])


# ------------------------------------------------------------------ offline


@pytest.mark.needs_libclang
def test_a_full_scan_writes_three_artifacts_and_exits_with_findings(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """The whole M1 pipeline, offline: exit 1 because something was confirmed."""
    root, database = demo_project(tmp_path)
    out = tmp_path / "out"

    assert _run(root, database, out) == int(ExitCode.FINDINGS)

    report, sarif, manifest = _artifacts(out)
    assert "# C Audit report" in report
    assert "## Confirmed findings" in report
    assert "## Needs review" in report
    assert "## Coverage" in report

    schema = json.loads((SCHEMA_DIR / "sarif-2.1.0.schema.json").read_text(encoding="utf-8"))
    assert list(Draft4Validator(schema).iter_errors(sarif)) == []

    assert manifest.coverage.confirmed_count >= 1
    assert {tool.name for tool in manifest.tools} >= {"clang", "clang-tidy", "libclang"}
    assert manifest.policy_versions["profile"] == "1"
    assert manifest.models == []


@pytest.mark.needs_libclang
def test_two_scans_of_one_revision_produce_identical_report_and_sarif(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """AC-08-7 through the CLI, not just through the renderers."""
    root, database = demo_project(tmp_path)

    assert _run(root, database, tmp_path / "first") == int(ExitCode.FINDINGS)
    assert _run(root, database, tmp_path / "second") == int(ExitCode.FINDINGS)

    for name in ("report.md", "results.sarif"):
        assert (tmp_path / "first" / name).read_bytes() == (tmp_path / "second" / name).read_bytes()

    from caudit.report.manifest import reproducibility_diff

    first = _artifacts(tmp_path / "first")[2]
    second = _artifacts(tmp_path / "second")[2]
    assert reproducibility_diff(first, second) == {}


@pytest.mark.needs_libclang
def test_a_scan_with_nothing_to_report_still_writes_the_three_files(
    tmp_path: Path, no_analyzers: None
) -> None:
    """No analyzer ran, so exit 3 — and the report says why, in the report."""
    root, database = demo_project(tmp_path)
    out = tmp_path / "out"

    code = _run(
        root,
        database,
        out,
    )
    assert code == int(ExitCode.ENVIRONMENT)

    report, sarif, manifest = _artifacts(out)
    assert "No analyzer ran" in report
    assert "## Confirmed findings (0)" in report
    assert "## Coverage" in report
    assert manifest.coverage.confirmed_count == 0
    notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]  # type: ignore[index]
    assert any("No analyzer ran" in note["message"]["text"] for note in notifications)


@pytest.mark.needs_libclang
def test_the_written_report_names_no_absolute_path(tmp_path: Path, stubbed_analyzers: None) -> None:
    """AC-08-11 as the user sees it, on a real output directory."""
    root, database = demo_project(tmp_path)
    out = tmp_path / "out"
    _run(root, database, out)

    for name in ("report.md", "results.sarif"):
        text = (out / name).read_text(encoding="utf-8")
        assert str(root) not in text
        assert str(tmp_path) not in text
    assert str(root) in (out / "run-manifest.json").read_text(encoding="utf-8")


# ---------------------------------------------------------------- T-08-17


@pytest.mark.needs_clang
@pytest.mark.needs_libclang
@pytest.mark.parametrize("case_id", ["oob-write-stack-copy", "null-deref-unchecked-alloc"])
def test_a_real_toolchain_writes_a_valid_reproducible_report(case_id: str, tmp_path: Path) -> None:
    """T-08-17: the real analyzers, the real artifacts, twice.

    Deselected by default. On a machine with Clang this is what confirms that
    the offline stubs above stand in for something real.
    """
    from caudit.eval.adapters.mini import MiniSuite

    suite = MiniSuite()
    case_root = suite.root / case_id
    database = suite.materialize_compile_commands(case_id, tmp_path / "db")

    first = tmp_path / "first"
    second = tmp_path / "second"
    codes = [
        main(
            [
                "--set",
                "intake.allow_partial_coverage=true",
                "scan",
                str(case_root),
                "--compile-commands",
                str(database),
                "--out",
                str(out),
            ]
        )
        for out in (first, second)
    ]
    assert codes[0] == codes[1]
    assert codes[0] in {int(ExitCode.OK), int(ExitCode.FINDINGS)}

    report, sarif, manifest = _artifacts(first)
    schema = json.loads((SCHEMA_DIR / "sarif-2.1.0.schema.json").read_text(encoding="utf-8"))
    assert list(Draft4Validator(schema).iter_errors(sarif)) == []
    assert "# C Audit report" in report

    # Exit 1 exactly when something was confirmed; 0 exactly when nothing was.
    expected = ExitCode.FINDINGS if manifest.coverage.confirmed_count else ExitCode.OK
    assert codes[0] == int(expected)

    for name in ("report.md", "results.sarif"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
