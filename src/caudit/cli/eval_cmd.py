"""``caudit eval`` and ``caudit compare``.

Rendering keeps confirmed findings and review-required candidates under
separate headings, with no combined total anywhere on the page. That is the
spec's rule, and a report is where it is easiest to break by accident.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter

from rich.console import Console
from rich.table import Table

from caudit.analyzers.profile import ProfileError, load_profile
from caudit.application.evaluation import (
    EvalResult,
    default_source,
    run_suite,
    select_cases,
    write_metrics,
)
from caudit.application.providers import gemini_provider_factory
from caudit.config.loader import Config
from caudit.errors import CauditError, UsageError
from caudit.eval.adapters.castle import CastleSuite
from caudit.eval.adapters.juliet import JulietSuite
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.adapters.pairs import PairsSuite
from caudit.eval.adjudicated import AdjudicatedSource, CompileCommandsFor
from caudit.eval.baseline import CandidateSource, RecordedCandidateSource
from caudit.eval.case import BenchmarkSuite
from caudit.eval.compare import CostSummary
from caudit.eval.experiment import ExperimentCondition
from caudit.eval.gates import KNOWN_PRODUCER_TOOLS, GateResult, model_producer_tools
from caudit.eval.metrics import Metrics
from caudit.eval.profiled import ProfiledCandidateSource
from caudit.eval.trace import TraceWriter
from caudit.llm.service import LLMProvider, consent_state, response_cache
from caudit.status import ExitCode

__all__ = [
    "candidate_source",
    "refuse_unrecorded_cases",
    "render_metrics",
    "resolve_suite",
    "run_eval",
]

from collections.abc import Callable

_SUITES: dict[str, Callable[[], BenchmarkSuite]] = {
    "mini": MiniSuite,
    "castle": CastleSuite,
    "juliet": JulietSuite,
    "pairs": PairsSuite,
}


def resolve_suite(name: str) -> BenchmarkSuite:
    factory = _SUITES.get(name.strip().lower())
    if factory is None:
        raise UsageError(f"unknown suite '{name}'", hint=f"Available: {', '.join(sorted(_SUITES))}")
    return factory()


def run_eval(
    *,
    config: Config,
    suite: str,
    baseline: bool,
    out_dir: Path,
    case_ids: Sequence[str] = (),
    console: Console | None = None,
    use_clang: bool = False,
    provider: LLMProvider | None = None,
    baseline_metrics: Path | None = None,
) -> ExitCode:
    """Score a suite and apply the hard gates. Returns the process exit code.

    ``provider`` is injectable so an adjudicated run can be scored from
    committed cassettes with no socket and no key. Left ``None`` on a
    ``--no-baseline`` run, the backend is constructed from the consent
    decision, and without consent the run stops rather than quietly falling
    back to the baseline and reporting it as an adjudicated score.
    """
    out = console or Console(soft_wrap=True, highlight=False)
    benchmark = resolve_suite(suite)
    if not benchmark.case_ids():
        raise CauditError(
            f"suite '{suite}' has no cases available",
            hint="For castle/juliet, fetch the corpus first; see the adapter's hint.",
        )

    source = candidate_source(config, benchmark, out_dir, use_clang=use_clang)
    refuse_unrecorded_cases(source, benchmark, case_ids)
    adjudicator = None if baseline else _adjudicator(config, benchmark, out_dir, provider=provider)

    run_id = uuid.uuid4().hex[:12]
    out_dir.mkdir(parents=True, exist_ok=True)
    trace_path = out_dir / f"trace-{benchmark.name}.jsonl"
    # Wall time is the latency figure the M2 checklist asks for, and it is a
    # property of the run rather than of the scores — so it goes in the run
    # report beside the cost, never into the metrics themselves.
    began = perf_counter()

    with TraceWriter(
        trace_path,
        run_id=run_id,
        policy_version=config.policy_versions.matching,
        tool_versions=dict(source.tool_versions()),
    ) as trace:
        result = run_suite(
            benchmark,
            source=source,
            case_ids=case_ids,
            max_file_bytes=config.token_budget.max_file_bytes,
            trace=trace,
            baseline=_load_baseline(baseline_metrics),
            is_baseline_run=baseline,
            adjudicator=adjudicator,
            # The deterministic floor plus the models *this configuration* is
            # allowed to call. Model ids are configuration, so a static list
            # cannot know them, and the one compiled in said `gemini` while
            # every real run records `gemini-flash-latest` — which fired the
            # fabrication gate on every adjudicated run.
            known_tools=KNOWN_PRODUCER_TOOLS | model_producer_tools(config),
        )
        trace.write("tool_versions_final", tool_versions=dict(result.tool_versions))
        if adjudicator is not None and adjudicator.unindexed:
            trace.write("cases_not_indexed", case_ids=sorted(adjudicator.unindexed))

    metrics_path = write_metrics(
        result,
        out_dir / f"metrics-{benchmark.name}.json",
        policy_versions=_policy_versions(config),
        cost=_cost(adjudicator, wall_seconds=perf_counter() - began),
        adjudicated=not baseline,
        config=config,
        experiment_condition=(
            ExperimentCondition.ANALYZER_CONTROL if baseline else ExperimentCondition.ADJUDICATED
        ),
    )
    render_metrics(result, out)
    if isinstance(source, ProfiledCandidateSource) and source.unanalysed:
        _report_missing(
            sorted(source.unanalysed),
            out,
            reason="no analyzer ran over them",
            consequence=(
                "They contributed no candidates, which scores the same as a case "
                "the analyzers cleared. It is not the same thing."
            ),
        )
    _report_unindexed(adjudicator, out)
    out.print(f"\nmetrics: {metrics_path}\ntrace:   {trace_path}")

    if result.passed:
        return ExitCode.OK
    out.print("\nHard gates failed. No overall score is reported while any gate is failing.")
    return ExitCode.FINDINGS


def _load_baseline(path: Path | None) -> Metrics | None:
    """The analyzer-only metrics this run has to beat, read from disk.

    The ``baseline_floor`` gate exists because the spec requires recall and
    precision floors to be established against the analyzers before an overall
    score means anything. Without a way to supply them, an adjudicated run
    failed that gate unconditionally — it had nothing to compare against and
    no argument could be passed to give it one, so `caudit eval --no-baseline`
    could never pass its own gates.
    """
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(
            f"cannot read the baseline metrics at {path}",
            hint="Produce one with 'caudit eval --baseline --use-clang --out <dir>'.",
        ) from exc
    return Metrics.model_validate(payload["metrics"])


def candidate_source(
    config: Config, suite: BenchmarkSuite, out_dir: Path, *, use_clang: bool
) -> CandidateSource:
    """Where candidates come from, and why that is the shipped answer.

    Public because ``caudit ablate`` needs the same answer. It must never call
    :func:`~caudit.application.evaluation.default_source` with ``use_clang=True`` instead:
    that returns part 04's :class:`ClangBaselineSource`, which is the different
    ruleset described below, and a grid scored with it would measure a tool
    this project does not ship -- the second of the four defects that made every
    pre-2026-08-15 number meaningless, reintroduced on a different command.

    ``--use-clang`` runs :class:`ProfiledCandidateSource`, which is the same
    ``generate_candidates`` pass ``caudit scan`` runs, under the same curated
    profile. Part 04's ``ClangBaselineSource`` enables a different ruleset in
    both directions — no compiler diagnostics, and the whole
    ``clang-analyzer-*`` glob rather than the checkers the profile picked — so
    scoring with it measures a tool this project does not ship. See
    :mod:`caudit.eval.profiled` for what that cost on the mini suite.
    """
    if not use_clang:
        return default_source(use_clang=False)
    return ProfiledCandidateSource(
        config=config,
        compile_commands=CompileCommandsFor(suite, out_dir / "compile-commands"),
        out_dir=out_dir / "analyzer-output",
    )


def refuse_unrecorded_cases(
    source: CandidateSource, suite: BenchmarkSuite, case_ids: Sequence[str]
) -> None:
    """Stop before scoring a suite the recorded source cannot replay.

    Public because ``caudit ablate`` needs it too, and needed it more: until
    this revision the grid skipped this check entirely, so a recorded run over
    an unrecorded corpus produced a full table of zeroes with the control and
    the baseline tied at nothing.

    A case with no recording contributes no candidates, which is
    indistinguishable from a case the analyzers cleared — so a suite that was
    never recorded scores a corpus-wide zero and every gate passes vacuously
    over it. Only ``mini`` ships recordings; pointing ``--recorded`` at CASTLE
    or Juliet is always this mistake, and the number it produces is exactly the
    kind of empty result the docs forbid reading as a measurement.
    """
    if not isinstance(source, RecordedCandidateSource):
        return
    absent = source.missing_recordings(select_cases(suite, case_ids))
    if not absent:
        return
    shown = ", ".join(absent[:5]) + (f", and {len(absent) - 5} more" if len(absent) > 5 else "")
    # UsageError, not a bare CauditError: pointing `--recorded` at a corpus that
    # ships no recordings is a configuration mistake and nothing was analysed,
    # which is what ExitCode.USAGE means. A bare CauditError exits INTERNAL,
    # and INTERNAL is declared for neither `eval` nor `ablate` in
    # COMMAND_EXIT_CODES.
    raise UsageError(
        f"{len(absent)} case(s) in suite '{suite.name}' have no committed analyzer "
        f"recording to replay: {shown}",
        hint=(
            "Re-run with --use-clang to run the real analyzers over them. Scoring "
            "them as recorded would report zero findings for every one, which is "
            "a corpus that was never measured, not a corpus that came back clean."
        ),
    )


def _report_missing(
    cases: Sequence[str], console: Console, *, reason: str, consequence: str
) -> None:
    """Name the cases a stage could not do its job on.

    Both callers record this in the trace already. The trace is not where
    somebody reads a score, and a partial run whose gaps are only in the trace
    prints exactly like a complete one.
    """
    console.print(f"\n{len(cases)} case(s): {reason}", style="bold")
    console.print("  " + ", ".join(cases))
    console.print(f"  {consequence}")


def _report_unindexed(adjudicator: AdjudicatedSource | None, console: Console) -> None:
    """Say on the page which cases the model never saw.

    These were scored on the analyzers alone because they could not be indexed,
    so they carry the baseline's answer inside a run labelled adjudicated. That
    was recorded only in the trace, where a comparison that is silently against
    the baseline on part of the corpus looks like a comparison.
    """
    if adjudicator is None or not adjudicator.unindexed:
        return
    _report_missing(
        sorted(adjudicator.unindexed),
        console,
        reason=(
            "could not be indexed and were scored on the analyzers alone, with no model involved"
        ),
        consequence=(
            "Their numbers are the baseline's. A comparison including them "
            "understates the difference it is measuring."
        ),
    )


def _policy_versions(config: Config) -> dict[str, str]:
    """Every policy version that shaped this run, spelled as the scan spells it.

    ``profile`` is the check profile's own *version*, not the name it was
    selected by. The scan manifest records the version, and using the name here
    would put two different things under one key — so a comparison of two runs
    that enabled different checks under one profile name would pass.
    """
    versions = {key: str(value) for key, value in config.policy_versions.model_dump().items()}
    try:
        versions["profile"] = load_profile(config.analyzers.profile).version
    except ProfileError:
        # An unreadable profile is a real problem, but not this function's to
        # report: candidate generation raises on it with a usable message. An
        # unrecorded version here becomes a stated caveat in `caudit compare`
        # rather than a version nobody can check.
        versions.pop("profile", None)
    return versions


def _cost(adjudicator: AdjudicatedSource | None, *, wall_seconds: float) -> CostSummary:
    """What this run spent. Wall time always; the rest only if a model ran.

    A baseline run reports zero tokens and zero spend, which is the truth
    rather than a placeholder: nothing was sent. Wall time is still recorded,
    because the latency the comparison reports is the *difference* between the
    two, and a baseline with no duration would make that difference the
    adjudicated run's whole runtime.
    """
    if adjudicator is None:
        return CostSummary(wall_seconds=wall_seconds)
    account = adjudicator.account
    return CostSummary(
        calls=account.calls,
        input_tokens=sum(a.usage.input_tokens for a in account.accounts.values()),
        output_tokens=sum(a.usage.output_tokens for a in account.accounts.values()),
        usd=account.cost_usd(),
        wall_seconds=wall_seconds,
    )


def _adjudicator(
    config: Config,
    suite: BenchmarkSuite,
    out_dir: Path,
    *,
    provider: LLMProvider | None,
) -> AdjudicatedSource:
    """The model-in-the-loop scorer, or a refusal naming what is missing.

    Consent is checked here rather than inside the source, so a run that may
    not transmit anything never gets as far as constructing a backend. Falling
    back to the analyzer-only path would be worse than stopping: the run would
    finish, write a file labelled ``adjudicated``, and record the baseline's
    numbers under it.
    """
    consent = consent_state(config)
    if not consent.granted and provider is None:
        raise UsageError(
            "adjudicated evaluation sends source regions to a hosted model, and this "
            "run has no consent to do that",
            hint=(
                "Re-run with '--set cloud_consent=true' and GEMINI_API_KEY in the "
                "environment, or use --baseline to measure the analyzers alone."
            ),
        )
    backend = provider if provider is not None else gemini_provider_factory(consent)
    return AdjudicatedSource(
        config=config,
        provider=backend,
        consent=consent,
        compile_commands=CompileCommandsFor(suite, out_dir / "compile-commands"),
        analyzers=sorted(KNOWN_PRODUCER_TOOLS),
        cache=response_cache(config, out_dir),
    )


def render_metrics(result: EvalResult, console: Console) -> None:
    """Print per-family metrics, the two counts, and the gates."""
    metrics = result.metrics

    families = Table(title=f"Per-family detection — suite '{metrics.suite}'")
    for column in ("family", "tp", "fp", "fn", "precision", "recall", "F2"):
        families.add_column(column)
    for family_metrics in metrics.per_family.values():
        families.add_row(
            str(family_metrics.family),
            str(family_metrics.true_positives),
            str(family_metrics.false_positives),
            str(family_metrics.false_negatives),
            f"{family_metrics.precision:.3f}",
            f"{family_metrics.recall:.3f}",
            f"{family_metrics.f2:.3f}",
        )
    console.print(families)

    summary = Table(title="Security summary", show_header=False)
    summary.add_column("metric")
    summary.add_column("value")
    summary.add_row("macro-F2 (β=2, recall-weighted)", f"{metrics.macro_f2:.4f}")
    summary.add_row("false positives per KLOC", f"{metrics.fp_per_kloc:.3f}")
    summary.add_row("citation resolution rate", f"{metrics.citation_resolution_rate:.4f}")
    summary.add_row("evidence validity rate", f"{metrics.evidence_validity_rate:.4f}")
    summary.add_row("matching policy version", metrics.policy_version)
    summary.add_row("cases scored", str(metrics.case_count))
    console.print(summary)

    # Two headings, never one number. Merging these is what the spec forbids.
    # Styled through `style=`, because the console has markup disabled.
    console.print("\nConfirmed findings", style="bold")
    console.print(f"  {metrics.confirmed_count}")
    console.print("Needs review (review-required candidates)", style="bold")
    console.print(f"  {metrics.review_required_count}")
    console.print("  Counted separately by design; these two numbers are never added together.")

    if metrics.blind_spot_case_ids:
        console.print(
            "\nCases marked as known analyzer blind spots: "
            + ", ".join(metrics.blind_spot_case_ids)
        )

    gates = Table(title="Hard gates")
    for column in ("gate", "verdict", "observed", "threshold", "detail"):
        gates.add_column(column, overflow="fold")
    for gate in result.gates:
        gates.add_row(
            gate.name,
            "pass" if gate.passed else "FAIL",
            str(gate.observed),
            str(gate.threshold),
            gate.detail,
        )
    console.print(gates)


def gate_summary(gates: Sequence[GateResult]) -> str:
    """One-line summary used by callers that do not render a table."""
    failed = [gate.name for gate in gates if not gate.passed]
    return "all gates passed" if not failed else "failed: " + ", ".join(failed)
