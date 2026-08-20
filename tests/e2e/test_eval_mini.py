"""Part 04 end-to-end tests: T-04-16, T-04-17, T-04-18.

These run the real CLI over the committed mini suite. Nothing here opens a
socket, downloads a corpus, or needs a compiler — which is the whole point of
AC-04-9.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from caudit.cli.main import main
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.trace import read_trace
from caudit.model.cwe import WeaknessFamily
from caudit.status import ExitCode


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any socket attempt during these tests is a test failure."""

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the mini suite must not open a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def test_mini_suite_runs_offline_and_covers_six_families(
    tmp_path: Path, no_network: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-04-16: `caudit eval --suite mini --baseline`, no network, six families."""
    code = main(["eval", "--suite", "mini", "--baseline", "--out", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == ExitCode.OK, captured.out

    suite = MiniSuite()
    cases = suite.cases()
    assert len(cases) == 6
    families = {truth.family for case in cases for truth in case.ground_truth}
    assert families == set(WeaknessFamily), "one case per in-scope weakness family"

    payload = json.loads((tmp_path / "metrics-mini.json").read_text(encoding="utf-8"))
    assert payload["metrics"]["case_count"] == 6
    assert payload["metrics"]["suite"] == "mini"


def test_the_suite_does_not_score_perfectly(tmp_path: Path) -> None:
    """A mini suite where everything passes would be evidence of a bug.

    Two cases are deliberately built to defeat single-TU analysis; if the
    baseline ever scores 1.0 here, either the fixtures drifted or the harness
    started crediting something it should not.
    """
    main(["eval", "--suite", "mini", "--out", str(tmp_path)])
    payload = json.loads((tmp_path / "metrics-mini.json").read_text(encoding="utf-8"))
    metrics = payload["metrics"]
    assert 0.0 < metrics["macro_f2"] < 1.0
    # Measured against clang 18.1.3 on 2026-08-15, not predicted. The pairing
    # changed when the suite was first scored on a real toolchain: see
    # benchmarks/mini/README.md for which two flags moved and why.
    assert set(metrics["blind_spot_case_ids"]) == {
        "integer-truncation-alloc",
        "null-deref-unchecked-alloc",
    }
    for case_id in metrics["blind_spot_case_ids"]:
        assert case_id in {c.case_id for c in MiniSuite().cases()}


def test_trace_records_policy_version_tool_versions_and_timings(
    tmp_path: Path,
) -> None:
    """T-04-17."""
    main(["eval", "--suite", "mini", "--out", str(tmp_path)])
    records = read_trace(tmp_path / "trace-mini.jsonl")
    assert records, "the trace must not be empty"

    events = [record["event"] for record in records]
    assert events[0] == "run_started"
    assert events[-1] == "run_finished"
    assert "metrics" in events
    assert events.count("case_scored") == 6

    assert all(record["policy_version"] == "1" for record in records)
    assert all(record["run_id"] == records[0]["run_id"] for record in records)

    scored = [r for r in records if r["event"] == "case_scored"]
    assert all("candidates" in r and "findings" in r for r in scored)
    assert all("lines_of_code" in r for r in scored)

    final = next(r for r in records if r["event"] == "tool_versions_final")
    assert "clang-tidy" in final["tool_versions"]


def test_two_runs_produce_identical_metrics(tmp_path: Path) -> None:
    """T-04-18: identical scores, so a regression cannot hide in jitter.

    Part 12 added a ``cost`` block carrying wall time, so the file as a whole
    is no longer byte-identical — the same reason ``run-manifest.json`` never
    was. Everything that describes *what was found* still is, and that is what
    the gate was ever about; the run report's own comparison rule
    (:func:`caudit.eval.compare.compare_runs`) draws the line in the same
    place.
    """
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    main(["eval", "--suite", "mini", "--out", str(first_dir)])
    main(["eval", "--suite", "mini", "--out", str(second_dir)])

    first = json.loads((first_dir / "metrics-mini.json").read_text(encoding="utf-8"))
    second = json.loads((second_dir / "metrics-mini.json").read_text(encoding="utf-8"))

    for key in ("metrics", "gates", "tool_versions", "policy_versions", "scope", "adjudicated"):
        assert first[key] == second[key], key
    # The only difference is how long it took, and it is confined to one field.
    assert first["cost"].keys() == second["cost"].keys()
    assert {k: v for k, v in first["cost"].items() if k != "wall_seconds"} == {
        k: v for k, v in second["cost"].items() if k != "wall_seconds"
    }


def test_unknown_suite_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["eval", "--suite", "nonesuch", "--out", str(tmp_path)])
    assert code == ExitCode.USAGE
    assert "nonesuch" in capsys.readouterr().err


def test_unknown_case_id_is_reported(tmp_path: Path) -> None:
    from caudit.application.evaluation import run_suite

    with pytest.raises(KeyError, match="no-such-case"):
        run_suite(MiniSuite(), case_ids=["no-such-case"])


def test_adjudicated_mode_refuses_to_run_without_consent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--no-baseline`` sends source to a model, so it stops without consent.

    Stopping is the point. Falling back to the analyzer-only path would finish
    the run, write a file marked ``adjudicated``, and record the baseline's
    numbers under it — which is exactly the measurement nobody could trust.
    """
    code = main(["eval", "--suite", "mini", "--no-baseline", "--out", str(tmp_path)])
    assert code == ExitCode.USAGE

    message = capsys.readouterr().err
    assert "no consent" in message
    assert "--baseline" in message
    assert not (tmp_path / "metrics-mini.json").exists()


def test_compare_refuses_reports_from_different_policy_versions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-04-10 through the CLI."""
    main(["eval", "--suite", "mini", "--out", str(tmp_path)])
    original = tmp_path / "metrics-mini.json"
    altered = tmp_path / "metrics-v2.json"
    payload = json.loads(original.read_text(encoding="utf-8"))
    payload["metrics"]["policy_version"] = "2"
    altered.write_text(json.dumps(payload), encoding="utf-8")

    code = main(["compare", str(original), str(altered)])
    assert code == ExitCode.USAGE
    assert "not comparable" in capsys.readouterr().err


def test_compare_reports_deltas_for_matching_policy_versions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["eval", "--suite", "mini", "--out", str(tmp_path)])
    metrics = tmp_path / "metrics-mini.json"
    code = main(["compare", str(metrics), str(metrics)])
    assert code == ExitCode.OK
    output = capsys.readouterr().out
    assert "macro_f2" in output
    assert "confirmed_count" in output
    assert "review_required_count" in output
