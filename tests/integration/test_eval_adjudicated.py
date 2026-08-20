"""The Milestone 2 measurement path, offline.

``caudit eval --no-baseline`` scores the mini suite with the model in the loop:
each case is indexed through the ``libclang`` wheel, every candidate is
expanded, adjudicated and gated, and the result goes through the same matching
policy and the same hard gates as the baseline. Differencing the two is what
:mod:`caudit.eval.compare` does.

What is exercised here is the *machinery*, driven by
:class:`~tests.conftest.ScriptedProvider`. The number that closes M2 needs a
real model and an API key, and no test in the default suite can produce it —
the same standing as T-07-21, T-08-17 and T-10-21. What this does establish is
that the harness runs end to end, that both sides are scored by identical code
below the adjudicator, and that a comparison of the two is well-formed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.application.evaluation import run_suite, write_metrics
from caudit.config.loader import Config
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.adjudicated import AdjudicatedSource, CompileCommandsFor
from caudit.eval.compare import CostSummary, RunReport, compare_runs
from caudit.eval.gates import KNOWN_PRODUCER_TOOLS
from tests.conftest import ScriptedProvider, granted_consent

CASES = ("oob-write-stack-copy", "uaf-double-free")


def _config() -> Config:
    return Config.model_validate(
        {
            "cloud_consent": True,
            "index": {"in_process": True},
            "llm": {"triage_enabled": False, "cache_enabled": False},
        }
    )


def _source(tmp_path: Path, provider: ScriptedProvider) -> AdjudicatedSource:
    suite = MiniSuite()
    return AdjudicatedSource(
        config=_config(),
        provider=provider,
        consent=granted_consent(),
        compile_commands=CompileCommandsFor(suite, tmp_path / "compile-commands"),
        analyzers=sorted(KNOWN_PRODUCER_TOOLS),
    )


@pytest.mark.needs_libclang
def test_the_adjudicated_run_scores_the_suite_and_reaches_the_provider(
    tmp_path: Path,
) -> None:
    """The whole path: index, expand, adjudicate, gate, score, gate again."""
    provider = ScriptedProvider()
    source = _source(tmp_path, provider)

    result = run_suite(MiniSuite(), case_ids=CASES, adjudicator=source, is_baseline_run=False)

    assert provider.calls > 0, "no candidate reached the model"
    assert set(result.findings_by_case) == set(CASES)
    assert source.unindexed == [], source.unindexed
    assert source.account.calls > 0
    # Every candidate still produces exactly one finding: nothing is discarded
    # by putting a model in the middle.
    assert all(findings for findings in result.findings_by_case.values())


@pytest.mark.needs_libclang
def test_the_two_counts_stay_apart_through_the_adjudicated_harness(tmp_path: Path) -> None:
    """The spec's rule survives the path that has the most steps in it."""
    result = run_suite(
        MiniSuite(),
        case_ids=CASES,
        adjudicator=_source(tmp_path, ScriptedProvider()),
        is_baseline_run=False,
    )
    metrics = result.metrics

    assert not hasattr(metrics, "total_findings")
    for case_findings in result.findings_by_case.values():
        confirmed = [f for f in case_findings if f.is_confirmed]
        review = [f for f in case_findings if not f.is_confirmed]
        assert len(confirmed) + len(review) == len(case_findings)
        assert not {f.finding_id for f in confirmed} & {f.finding_id for f in review}


@pytest.mark.needs_libclang
def test_a_case_that_cannot_be_indexed_falls_back_rather_than_vanishing(
    tmp_path: Path,
) -> None:
    """Dropping it would improve the score by removing the hard cases."""

    class NoDatabase(CompileCommandsFor):
        def __call__(self, case: object) -> Path | None:
            return None

    suite = MiniSuite()
    source = AdjudicatedSource(
        config=_config(),
        provider=ScriptedProvider(),
        consent=granted_consent(),
        compile_commands=NoDatabase(suite, tmp_path / "unused"),
        analyzers=sorted(KNOWN_PRODUCER_TOOLS),
    )
    result = run_suite(suite, case_ids=CASES, adjudicator=source, is_baseline_run=False)

    assert sorted(source.unindexed) == sorted(CASES)
    assert set(result.findings_by_case) == set(CASES)
    assert all(findings for findings in result.findings_by_case.values())
    assert source.account.calls == 0


@pytest.mark.needs_libclang
def test_the_baseline_and_the_adjudicated_run_are_comparable(tmp_path: Path) -> None:
    """AC-12-9 over two real runs of one suite, not two hand-built metrics.

    Both sides are scored by identical code below the adjudicator, which is
    what makes the delta attributable to the model rather than to the scorer.
    """
    policies = {**_config().policy_versions.model_dump(), "profile": "security"}

    baseline_result = run_suite(MiniSuite(), case_ids=CASES, is_baseline_run=True)
    adjudicated_result = run_suite(
        MiniSuite(),
        case_ids=CASES,
        adjudicator=_source(tmp_path, ScriptedProvider()),
        is_baseline_run=False,
    )

    baseline = RunReport(
        metrics=baseline_result.metrics,
        gates=list(baseline_result.gates),
        policy_versions={"matching": "1", "profile": "security"},
        scope=sorted(baseline_result.findings_by_case),
        cost=CostSummary(wall_seconds=1.0),
    )
    adjudicated = RunReport(
        metrics=adjudicated_result.metrics,
        gates=list(adjudicated_result.gates),
        policy_versions=policies,
        scope=sorted(adjudicated_result.findings_by_case),
        cost=CostSummary(calls=8, input_tokens=8000, output_tokens=1600, wall_seconds=4.0),
        adjudicated=True,
    )

    report = compare_runs(baseline, adjudicated)

    assert report.cost.calls == 8
    assert report.cost.wall_seconds == pytest.approx(3.0)
    assert set(report.delta.per_family) >= set(baseline_result.metrics.per_family)
    # The comparison is well-formed whatever the numbers say; whether it is a
    # *result* depends on the gates, and this asserts the report says which.
    assert isinstance(report.valid, bool)
    assert report.headline()


def test_the_database_resolver_prefers_what_the_case_already_has(tmp_path: Path) -> None:
    """A case that carries its own database is not re-materialised."""
    suite = MiniSuite()
    case = suite.load("oob-write-stack-copy")
    existing = tmp_path / "compile_commands.json"
    existing.write_text("[]\n", encoding="utf-8")

    resolver = CompileCommandsFor(suite, tmp_path / "workspace")
    assert resolver(case.model_copy(update={"compile_commands": existing})) == existing
    # And a path that no longer exists falls through to the suite's template.
    missing = case.model_copy(update={"compile_commands": tmp_path / "gone.json"})
    assert resolver(missing) is not None


def test_a_suite_that_cannot_materialise_a_database_returns_nothing(tmp_path: Path) -> None:
    """``None`` is "this case cannot be indexed", never a silent skip."""

    class Bare:
        name = "bare"

    case = MiniSuite().load("oob-write-stack-copy")
    resolver = CompileCommandsFor(Bare(), tmp_path / "workspace")
    assert resolver(case) is None


def test_a_case_the_suite_does_not_know_returns_nothing(tmp_path: Path) -> None:
    suite = MiniSuite()
    case = suite.load("oob-write-stack-copy").model_copy(update={"case_id": "no-such-case"})
    assert CompileCommandsFor(suite, tmp_path / "workspace")(case) is None


@pytest.mark.needs_libclang
def test_the_model_tiers_that_answered_are_reported(tmp_path: Path) -> None:
    """The run report's tool list names the model, not just the analyzers."""
    source = _source(tmp_path, ScriptedProvider())
    run_suite(MiniSuite(), case_ids=CASES, adjudicator=source, is_baseline_run=False)

    versions = source.tool_versions()
    assert "model:adjudication" in versions
    assert versions["model:adjudication"] == _config().models.adjudication


@pytest.mark.needs_libclang
def test_the_written_run_report_records_that_a_model_was_involved(tmp_path: Path) -> None:
    """``adjudicated`` is recorded, not inferred from a zero cost.

    A cached adjudicated run also spends nothing, so cost cannot stand in for
    "a model participated" — which is the one fact the comparison is about.
    """
    result = run_suite(
        MiniSuite(),
        case_ids=CASES,
        adjudicator=_source(tmp_path, ScriptedProvider()),
        is_baseline_run=False,
    )
    path = write_metrics(
        result,
        tmp_path / "metrics.json",
        policy_versions={"matching": "1", "prompt": "2", "profile": "security"},
        cost=CostSummary(calls=8, wall_seconds=4.0),
        adjudicated=True,
    )

    from caudit.eval.compare import load_run_report

    written = load_run_report(path)
    assert written.adjudicated is True
    assert written.scope == sorted(CASES)
    assert written.policy_versions["prompt"] == "2"
    assert written.cost.calls == 8
