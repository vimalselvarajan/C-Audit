"""Part 13 runner tests: T-13-19 … T-13-22.

Covers AC-13-8 and AC-13-9 from the side the grid alone could not reach. The
grid decided what an ablation set must contain; these decide whether a row is
a *measurement* — whether varying a factor changes a run, whether a case that
could not be measured is excluded with a reason, and whether a grid run
without a model can be read as an answer about detection.

``needs_libclang``: measuring retrieval means indexing, and an index stub
would be testing the harness against itself.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from caudit.application.evaluation import default_source
from caudit.cli.ablate_cmd import render_suite, run_ablation
from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.eval.ablation import (
    AblationConfig,
    AblationMode,
    AblationResult,
    AblationSuite,
    RetrievalVariant,
    ablation_grid,
    run_grid,
    vary,
)
from caudit.eval.ablation_runner import SuiteScorer, measure_retrieval
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.adjudicated import CompileCommandsFor
from caudit.eval.case import BenchmarkCase, GroundTruth
from caudit.status import ExitCode

pytestmark = pytest.mark.needs_libclang

POLICIES = {"matching": "1", "prompt": "2", "retrieval": "1"}


def _baseline() -> AblationConfig:
    return AblationConfig(
        name="baseline", token_budget=2_000_000, caller_depth=2, expansion_policy_version="1"
    )


def _scorer(tmp_path: Path, *, cases: tuple[str, ...] = ()) -> SuiteScorer:
    suite = MiniSuite()
    return SuiteScorer(
        suite=suite,
        config=Config(),
        workspace=tmp_path / "workspace",
        source=default_source(),
        case_ids=cases or tuple(suite.case_ids()),
        policy_versions=POLICIES,
    )


# ------------------------------------------------------------------ T-13-19


def test_the_control_and_the_baseline_are_measured_and_differ(tmp_path: Path) -> None:
    """T-13-19, AC-13-9: the flat-window control produces a real number.

    The measurement that needs no API key. Both rows must carry a coverage
    figure — the column a retrieval-only grid is read from — and the control
    must cost something different, or the two configurations are not reaching
    ``expand`` at all.
    """
    scorer = _scorer(tmp_path)
    baseline = _baseline()
    control = vary(baseline, "retrieval_variant", RetrievalVariant.FLAT_WINDOW)

    measured = scorer(baseline)
    measured_control = scorer(control)

    assert measured.mode is AblationMode.RETRIEVAL_ONLY
    assert measured.evidence_coverage is not None
    assert measured_control.evidence_coverage is not None
    assert measured.contexts_measured > 0
    # Same candidates, different retrieval: the token cost has to move.
    assert measured.tokens != measured_control.tokens


def test_varying_caller_depth_reaches_the_expansion_policy(tmp_path: Path) -> None:
    """AC-13-8: a factor the run cannot apply is a factor nobody can measure.

    Asserted on the configuration rather than on a score, because on a corpus
    of single-function cases the depth genuinely changes nothing — and a test
    that demanded a different number here would be demanding a fixture, not a
    behaviour.
    """
    applied = vary(_baseline(), "caller_depth", 0).apply_to(Config())

    assert applied.retrieval.caller_depth == 0
    assert Config().retrieval.caller_depth == 2


def test_varying_the_variant_reaches_the_expansion_policy() -> None:
    """The same for the control, which is the factor the grid must never lose."""
    applied = vary(_baseline(), "retrieval_variant", RetrievalVariant.FLAT_WINDOW).apply_to(
        Config()
    )

    assert applied.retrieval.variant == "flat_window"


# ------------------------------------------------------------------ T-13-20


def test_a_case_that_cannot_be_indexed_is_excluded_with_a_reason(tmp_path: Path) -> None:
    """T-13-20, AC-13-3: excluded from both halves of the fraction, and named.

    The suite here has no way to produce a compilation database, so every case
    is unmeasurable. What must not happen is a coverage of 0.0 — a corpus
    nothing could be measured on and a corpus retrieval missed entirely are
    opposite results.
    """
    suite = MiniSuite()
    measurement = measure_retrieval(
        list(suite.cases()),
        config=Config(),
        source=default_source(),
        compile_commands=CompileCommandsFor(object(), tmp_path),
    )

    assert measurement.coverage is None
    assert measurement.truths_total == 0
    assert {case.case_id for case in measurement.excluded} == set(suite.case_ids())
    # The reason names the adapter gap rather than the per-case one. Both are
    # exclusions and both yield coverage None, but "this suite can never produce
    # a database" and "this case's build failed" are different facts, and only
    # the second is about the corpus.
    assert all("materialize_compile_commands" in case.reason for case in measurement.excluded)


# ------------------------------------------------------------------ T-13-21


def test_a_retrieval_only_grid_never_answers_the_detection_question(
    tmp_path: Path,
) -> None:
    """T-13-21, AC-13-9: 'not measured' must not render as 'no'.

    Every retrieval-only row carries the analyzer-only score, so a comparison
    on ``macro_f2`` would return ``False`` every time — a confident verdict
    that structural retrieval does not earn itself, from an experiment in
    which no model read either context.
    """
    scorer = _scorer(tmp_path)
    grid = ablation_grid(_baseline())
    suite = run_grid(grid, scorer, name="mini", baseline_name="baseline", policy_versions=POLICIES)

    assert suite.control is not None
    assert all(result.mode is AblationMode.RETRIEVAL_ONLY for result in suite.results)
    assert suite.structural_retrieval_earns_itself() is None
    # The question it *can* answer is answered.
    assert suite.structural_retrieval_covers_more() is not None


def test_a_detection_grid_does_answer_it() -> None:
    """The same suite shape, measured with a model, is readable as a verdict."""

    def result(name: str, macro_f2: float, variant: RetrievalVariant) -> AblationResult:
        return AblationResult(
            config=AblationConfig(
                name=name,
                token_budget=1000,
                caller_depth=1,
                expansion_policy_version="1",
                retrieval_variant=variant,
            ),
            macro_f2=macro_f2,
            evidence_validity_rate=1.0,
            citation_resolution_rate=1.0,
            confirmed_count=1,
            review_required_count=0,
            mode=AblationMode.DETECTION,
        )

    suite = AblationSuite(
        name="detection",
        baseline_name="baseline",
        results=[
            result("baseline", 0.8, RetrievalVariant.STRUCTURAL),
            result("control", 0.5, RetrievalVariant.FLAT_WINDOW),
        ],
    )

    assert suite.structural_retrieval_earns_itself() is True


def test_one_retrieval_only_row_is_enough_to_withhold_the_verdict() -> None:
    """A mixed suite is not half an answer; it is not an answer."""

    def result(name: str, variant: RetrievalVariant, mode: AblationMode) -> AblationResult:
        return AblationResult(
            config=AblationConfig(
                name=name,
                token_budget=1000,
                caller_depth=1,
                expansion_policy_version="1",
                retrieval_variant=variant,
            ),
            macro_f2=0.9 if name == "baseline" else 0.1,
            evidence_validity_rate=1.0,
            citation_resolution_rate=1.0,
            confirmed_count=1,
            review_required_count=0,
            mode=mode,
        )

    suite = AblationSuite(
        name="mixed",
        baseline_name="baseline",
        results=[
            result("baseline", RetrievalVariant.STRUCTURAL, AblationMode.DETECTION),
            result("control", RetrievalVariant.FLAT_WINDOW, AblationMode.RETRIEVAL_ONLY),
        ],
    )

    assert suite.structural_retrieval_earns_itself() is None


# ------------------------------------------------------------------ T-13-22


def test_the_command_runs_a_grid_and_records_it(tmp_path: Path) -> None:
    """T-13-22, AC-13-8: ``caudit ablate`` end to end, offline.

    No consent, no provider, no socket — and a written record with the control
    in it. This is the path that makes part 13's ablation something a person
    can run rather than something a test can construct.
    """
    out = tmp_path / "ablation"
    code = run_ablation(
        config=Config(),
        suite="mini",
        out_dir=out,
        console=Console(file=StringIO(), width=200),
    )

    assert code is ExitCode.OK
    written = out / "ablation-mini.json"
    assert written.is_file()
    assert '"flat_window"' in written.read_text(encoding="utf-8")


class _UnrecordedSuite:
    """A suite whose cases ship no ``baseline-candidates.json``."""

    name = "stub"

    def __init__(self, cases: list[BenchmarkCase]) -> None:
        self._cases = cases

    def case_ids(self) -> list[str]:
        return [case.case_id for case in self._cases]

    def load(self, case_id: str) -> BenchmarkCase:
        return next(case for case in self._cases if case.case_id == case_id)

    def cases(self) -> list[BenchmarkCase]:
        return list(self._cases)


def test_a_recorded_grid_over_an_unrecorded_corpus_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-13-31, AC-13-8: the grid must not score a corpus it has no candidates for.

    ``caudit eval`` has refused this since part 04; ``caudit ablate`` did not,
    and it also never threaded ``--use-clang`` through, so *every* grid over
    every suite but ``mini`` built a ``RecordedCandidateSource`` with nothing to
    replay. The result was not an error: it was a full table in which the
    baseline and the flat-window control both scored zero on zero candidates
    and tied. A tie is the one outcome this command exists to distinguish from
    a win, so producing one from an empty corpus is the worst available answer.
    """
    # A stub rather than CASTLE: the refusal is about a suite with no
    # recordings, not about any particular corpus being fetched on this machine.
    case_root = tmp_path / "cases" / "only-case"
    case_root.mkdir(parents=True)
    (case_root / "a.c").write_text("int a(void)\n{\n    return 0;\n}\n", encoding="utf-8")
    suite = _UnrecordedSuite(
        [
            BenchmarkCase(
                case_id="only-case",
                root=case_root,
                ground_truth=[
                    GroundTruth(path="a.c", line=3, cwe="CWE-125", family="out_of_bounds")
                ],
                lines_of_code=4,
            )
        ]
    )
    monkeypatch.setattr("caudit.cli.eval_cmd.resolve_suite", lambda _name: suite)

    with pytest.raises(CauditError) as excinfo:
        run_ablation(
            config=Config(),
            suite="stub",
            out_dir=tmp_path / "ablation",
            use_clang=False,
            console=Console(file=StringIO(), width=200),
        )

    assert excinfo.value.exit_code is ExitCode.USAGE
    message = f"{excinfo.value} {excinfo.value.hint}"
    assert "no committed analyzer recording" in message
    assert "--use-clang" in message


def test_a_grid_that_made_no_call_is_not_a_detection_result(tmp_path: Path) -> None:
    """Consent without a reachable model is not a measurement of a model.

    ``--consent-cloud`` grants consent by itself, so this run constructs a
    provider and then fails on every request — no key is set here. Every
    candidate becomes provider-unavailable, which reads exactly like a model
    that found nothing. The row records zero calls, is labelled
    ``retrieval_only``, and the verdict stays ``not measured``.
    """
    log = StringIO()

    code = run_ablation(
        config=Config(),
        suite="mini",
        out_dir=tmp_path / "ablation",
        consent_cloud=True,
        console=Console(file=log, width=200),
    )

    assert code is ExitCode.OK
    printed = log.getvalue()
    assert "no call was made" in printed
    assert "retrieval_only" in printed
    assert "structural retrieval finds more than the flat window — not measured" in printed


def test_the_grid_is_reproducible(tmp_path: Path) -> None:
    """T-13-10 extended to a real scorer: two runs, one answer.

    Wall time is excluded, for the same reason ``caudit compare`` excludes it
    from a metrics comparison: it is a property of the machine, not of the
    configuration.
    """
    scorer = _scorer(tmp_path)
    grid = ablation_grid(_baseline())

    first = run_grid(grid, scorer, name="a", baseline_name="baseline", policy_versions=POLICIES)
    second = run_grid(grid, scorer, name="a", baseline_name="baseline", policy_versions=POLICIES)

    def comparable(suite: AblationSuite) -> list[dict[str, object]]:
        return [result.model_dump(exclude={"wall_time_s"}) for result in suite.results]

    assert comparable(first) == comparable(second)


def test_the_rendered_table_names_what_was_not_measured(tmp_path: Path) -> None:
    """The three-way answer reaches the page, not just the model."""
    scorer = _scorer(tmp_path)
    suite = run_grid(
        ablation_grid(_baseline()),
        scorer,
        name="mini",
        baseline_name="baseline",
        policy_versions=POLICIES,
    )
    log = StringIO()
    render_suite(suite, Console(file=log, width=200))

    printed = log.getvalue()
    assert "not measured" in printed
    assert "retrieval_only" in printed
