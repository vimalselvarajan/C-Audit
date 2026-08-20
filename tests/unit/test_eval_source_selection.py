"""Part 04: which analyzer output a scored suite is actually made of.

``caudit eval`` has two candidate sources and they are not interchangeable.
``--recorded`` replays a ``baseline-candidates.json`` committed beside each
case, which is what lets CI score the suite offline on a machine with no LLVM.
``--use-clang`` runs the real analyzers. Only the mini suite ships recordings.

The failure this module exists for is that the two are indistinguishable from
the outside when the recording is *missing*: ``RecordedCandidateSource``
returns no candidates, the case scores as though the analyzers had cleared it,
and a suite that was never recorded comes back as a corpus-wide zero with every
hard gate passing vacuously over it. There is no way to tell that apart from a
clean sweep by reading the metrics afterwards, so it has to be refused before
the run starts.

T-04-21 covers the refusal, T-04-22 the flag reaching the source, and T-04-23
the case a run is allowed to score zero for.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from caudit.application.evaluation import default_source
from caudit.cli.main import main
from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.eval.baseline import ClangBaselineSource, RecordedCandidateSource
from caudit.eval.case import BenchmarkCase, GroundTruth
from caudit.status import ExitCode


def _case(root: Path, case_id: str) -> BenchmarkCase:
    """A case whose root exists, with or without a recording beside it."""
    (root / case_id).mkdir(parents=True, exist_ok=True)
    (root / case_id / "a.c").write_text("int a(void)\n{\n    return 0;\n}\n", encoding="utf-8")
    return BenchmarkCase(
        case_id=case_id,
        root=root / case_id,
        ground_truth=[GroundTruth(path="a.c", line=3, cwe="CWE-125", family="out_of_bounds")],
        lines_of_code=4,
    )


class _Suite:
    """The smallest thing `run_eval` will accept as a suite."""

    name = "stub"

    def __init__(self, cases: list[BenchmarkCase]) -> None:
        self._cases = cases

    def case_ids(self) -> list[str]:
        return [case.case_id for case in self._cases]

    def load(self, case_id: str) -> BenchmarkCase:
        return next(case for case in self._cases if case.case_id == case_id)

    def cases(self) -> list[BenchmarkCase]:
        return list(self._cases)


def test_a_case_with_no_recording_is_reported_as_missing(tmp_path: Path) -> None:
    """T-04-21a: the source can say what it has nothing to replay for."""
    with_recording = _case(tmp_path, "recorded-case")
    (with_recording.root / "baseline-candidates.json").write_text(
        '{"diagnostics": []}', encoding="utf-8"
    )
    without = _case(tmp_path, "unrecorded-case")

    source = RecordedCandidateSource()
    assert source.missing_recordings([with_recording, without]) == ["unrecorded-case"]


def test_scoring_an_unrecorded_suite_is_refused_rather_than_scored_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-04-21: the whole point — a corpus nobody recorded is not a clean corpus.

    Without this the run completes, writes a metrics file, and every gate
    passes over zero findings. That number is indistinguishable from a real
    sweep and would be the most misleading artifact the harness can produce.
    """
    suite = _Suite([_case(tmp_path, "one"), _case(tmp_path, "two")])
    monkeypatch.setattr("caudit.cli.eval_cmd.resolve_suite", lambda _name: suite)

    from caudit.cli.eval_cmd import run_eval

    with pytest.raises(CauditError) as excinfo:
        run_eval(
            config=Config(),
            suite="stub",
            baseline=True,
            out_dir=tmp_path / "out",
            use_clang=False,
        )

    message = f"{excinfo.value} {excinfo.value.hint}"
    assert "one" in message and "two" in message
    assert "--use-clang" in message
    # The distinction the refusal exists to preserve, stated in the message
    # rather than left for the reader to infer from an empty table.
    assert "never measured" in message or "came back clean" in message
    assert not (tmp_path / "out").exists(), "refused before writing anything"


def test_the_refusal_does_not_fire_when_every_case_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-04-23: a recorded case that legitimately found nothing still scores.

    The guard must not turn "the analyzers cleared this case" into an error;
    that is a real result and the mini suite depends on being able to report
    it.
    """
    case = _case(tmp_path, "clean")
    (case.root / "baseline-candidates.json").write_text('{"diagnostics": []}', encoding="utf-8")
    monkeypatch.setattr("caudit.cli.eval_cmd.resolve_suite", lambda _name: _Suite([case]))

    from caudit.cli.eval_cmd import run_eval

    code = run_eval(
        config=Config(),
        suite="stub",
        baseline=True,
        out_dir=tmp_path / "out",
        use_clang=False,
    )
    assert code in {ExitCode.OK, ExitCode.FINDINGS}
    assert (tmp_path / "out" / "metrics-stub.json").is_file()


def test_use_clang_selects_the_real_analyzers() -> None:
    """T-04-22a: the two sources are distinct objects, not one with a flag."""
    assert isinstance(default_source(use_clang=True), ClangBaselineSource)
    assert isinstance(default_source(use_clang=False), RecordedCandidateSource)


@pytest.mark.needs_clang
def test_the_recorded_and_clang_paths_score_the_same_tool(tmp_path: Path) -> None:
    """T-04-24: the committed recordings replay the pass the scan actually runs.

    The two sources exist so CI can score offline, not so there can be two
    answers. They diverged silently for as long as the recorder used part 04's
    `ClangBaselineSource` while `caudit scan` used the curated profile: the
    published baseline credited detections the shipped tool does not make
    (`-Wformat-security` was not enabled) and charged false positives it does
    not produce (`insecureAPI.*` beyond `strcpy`). Equality here is what keeps
    a re-recording honest.
    """
    from caudit.cli.eval_cmd import run_eval

    scores = []
    for use_clang in (False, True):
        out_dir = tmp_path / ("clang" if use_clang else "recorded")
        run_eval(
            config=Config(),
            suite="mini",
            baseline=True,
            out_dir=out_dir,
            use_clang=use_clang,
        )
        metrics = json.loads((out_dir / "metrics-mini.json").read_text(encoding="utf-8"))["metrics"]
        scores.append(
            {
                key: metrics[key]
                for key in ("macro_f2", "fp_per_kloc", "confirmed_count", "review_required_count")
            }
        )

    assert scores[0] == scores[1], (
        "the committed recordings and the real analyzers disagree; re-run "
        "`make record-baseline` — a recording that replays a different ruleset "
        f"measures a tool nobody ships. recorded={scores[0]} clang={scores[1]}"
    )


def test_the_cli_flag_reaches_the_source(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """T-04-22: `--use-clang` is wired through, and `--recorded` is the default.

    This is the regression guard for the defect that made every published
    number a replay: `run_eval` accepted `use_clang` and the CLI never passed
    it, so the parameter existed and nothing could reach it.
    """
    seen: list[bool] = []

    def fake_run_eval(**kwargs: Any) -> ExitCode:
        seen.append(bool(kwargs["use_clang"]))
        return ExitCode.OK

    monkeypatch.setattr("caudit.cli.eval_cmd.run_eval", fake_run_eval)

    main(["eval", "--suite", "mini", "--use-clang", "--out", str(tmp_path / "a")])
    main(["eval", "--suite", "mini", "--recorded", "--out", str(tmp_path / "b")])
    main(["eval", "--suite", "mini", "--out", str(tmp_path / "c")])

    assert seen == [True, False, False], "default must stay recorded for offline CI"
