"""``caudit ablate`` — run the ablation grid and record what moved.

The command exists so part 13's grid is something a person can run rather than
something a test can construct. Everything it prints distinguishes three
answers where a table would usually offer two: yes, no, and **not measured**.
The third is the one this project has to keep saying, because a grid run
without a model cannot answer the detection question and must not appear to.

Consent works the way it does everywhere else: without it no provider is
constructed, and the grid runs in retrieval-only mode instead of quietly
producing a detection table nobody could trust. Consent alone is not enough to
earn the ``detection`` label, either — a row that meant to adjudicate and made
no call (no key, no route to the provider, a ceiling that bound immediately)
produces a grid of provider failures that reads exactly like a model finding
nothing, so it is recorded as ``retrieval_only`` and the run says why.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from caudit.application.providers import gemini_provider_factory
from caudit.config.loader import Config
from caudit.errors import UsageError
from caudit.eval.ablation import (
    AblationConfig,
    AblationMode,
    AblationSuite,
    RetrievalVariant,
    ablation_grid,
    run_grid,
    write_suite,
)
from caudit.eval.ablation_runner import SuiteScorer
from caudit.eval.gates import KNOWN_PRODUCER_TOOLS
from caudit.llm.service import consent_state
from caudit.status import ExitCode

__all__ = ["render_suite", "run_ablation"]


def run_ablation(
    *,
    config: Config,
    suite: str,
    out_dir: Path,
    case_ids: Sequence[str] = (),
    token_budgets: Sequence[int] = (),
    caller_depths: Sequence[int] = (),
    callee_depths: Sequence[int] = (),
    type_closure_depths: Sequence[int] = (),
    consent_cloud: bool = False,
    console: Console | None = None,
    use_clang: bool = False,
) -> ExitCode:
    """Score an ablation grid over one suite. Returns the process exit code."""
    from caudit.cli.eval_cmd import candidate_source, refuse_unrecorded_cases, resolve_suite

    out = console or Console(soft_wrap=True, highlight=False)
    benchmark = resolve_suite(suite)
    if not benchmark.case_ids():
        raise UsageError(
            f"suite '{suite}' has no cases available",
            hint="For castle/juliet/pairs, fetch or pin the corpus first; see the adapter's hint.",
        )
    out_dir.mkdir(parents=True, exist_ok=True)

    # The same two calls `run_eval` makes, in the same order, for the same
    # reasons. Both were missing here: the grid always built a
    # `RecordedCandidateSource` because `use_clang` was never threaded in from
    # the command line, and it never refused a corpus that had no recordings to
    # replay. Together those made `caudit ablate` over any suite but `mini`
    # report a grid of zeroes rather than an error -- the baseline and the
    # control tied at nothing, which reads as "the control is as good as
    # structural retrieval" and is the exact claim this command exists to test.
    source = candidate_source(config, benchmark, out_dir, use_clang=use_clang)
    refuse_unrecorded_cases(source, benchmark, case_ids)

    baseline = AblationConfig(
        name="baseline",
        token_budget=config.token_budget.per_run,
        caller_depth=config.retrieval.caller_depth,
        # `callee_depth` is `ge=1` on the grid while config allows 0; a
        # configuration that scans that way cannot be a baseline that measures
        # it, because depth 0 also suppresses the indirect-call limitation.
        callee_depth=max(1, config.retrieval.callee_depth),
        type_closure_depth=config.retrieval.type_closure_depth,
        expansion_policy_version=config.policy_versions.retrieval,
        tiers=config.models,
    )
    # The control is added by `ablation_grid` whether or not it was asked for.
    grid = ablation_grid(
        baseline,
        token_budgets=token_budgets,
        caller_depths=caller_depths,
        callee_depths=callee_depths,
        type_closure_depths=type_closure_depths,
        retrieval_variants=(RetrievalVariant.FLAT_WINDOW,),
    )

    # Consent decides whether a provider is constructed at all. Whether the
    # grid *measured* detection is decided afterwards, per row, by whether a
    # call was actually made — consent and a reachable model are two different
    # things, and only the second one produces an answer.
    consent = consent_state(_with_consent(config, consent_cloud))
    provider = gemini_provider_factory(consent) if consent.granted else None

    scorer = SuiteScorer(
        suite=benchmark,
        config=config,
        workspace=out_dir / "workspace",
        source=source,
        case_ids=case_ids,
        provider=provider,
        consent=consent if provider is not None else None,
        analyzers=sorted(KNOWN_PRODUCER_TOOLS),
        policy_versions={
            key: str(value) for key, value in config.policy_versions.model_dump().items()
        },
    )

    suite_result = run_grid(
        grid,
        scorer,
        name=f"{benchmark.name}-ablation",
        baseline_name=baseline.name,
        policy_versions=dict(scorer.policy_versions),
    )
    path = write_suite(suite_result, out_dir / f"ablation-{benchmark.name}.json")
    render_suite(suite_result, out)

    if scorer.adjudicating and all(not row.adjudication_calls for row in suite_result.results):
        out.print(
            "\nThis grid asked for a model and no call was made — a missing key, an "
            "unreachable provider, or a ceiling that bound immediately. Every row is "
            "recorded as retrieval_only rather than as a detection result, because a "
            "grid of provider failures reads exactly like a model that found nothing."
        )
    if scorer.excluded:
        out.print("\nExcluded (measured in neither numerator nor denominator):")
        for case in scorer.excluded:
            out.print(f"  {case.case_id}: {case.reason}")
    if not scorer.exclusions_agree:
        out.print(
            "\nThe configurations did not exclude the same cases, so the rows above were "
            "scored over different corpora and a delta between them is not attributable "
            "to the factor that varied. Per configuration:"
        )
        for name, cases in sorted(scorer.excluded_by_config.items()):
            ids = ", ".join(sorted(case.case_id for case in cases)) or "none"
            out.print(f"  {name}: {ids}")
    out.print(f"\nablation: {path}")
    return ExitCode.OK


def _with_consent(config: Config, consent_cloud: bool) -> Config:
    """Fold `--consent-cloud` in. Like `scan`'s, it can only turn consent on.

    An absent flag must never withdraw a consent recorded deliberately, and it
    must certainly never grant one.
    """
    if not consent_cloud:
        return config
    merged = config.model_dump()
    merged["cloud_consent"] = True
    return Config.model_validate(merged)


def render_suite(suite: AblationSuite, out: Console) -> None:
    """The grid as a table, then the two verdicts it can support."""
    table = Table(title=suite.name)
    table.add_column("configuration")
    table.add_column("measured")
    table.add_column("macro-F2", justify="right")
    table.add_column("evidence coverage", justify="right")
    table.add_column("tokens", justify="right")
    # The three scaling hazards, as columns rather than as prose. Each is a
    # count of candidates, so they are comparable with `contexts_measured`.
    table.add_column("starved", justify="right")
    table.add_column("over budget", justify="right")
    table.add_column("fn-ptr wall", justify="right")
    table.add_column("wall s", justify="right")

    for result in suite.results:
        table.add_row(
            result.config.name,
            str(result.mode),
            f"{result.macro_f2:.4f}",
            "—" if result.evidence_coverage is None else f"{result.evidence_coverage:.4f}",
            str(result.tokens),
            f"{result.starved_candidates}",
            f"{result.budget_exceeded_candidates}",
            f"{result.indirect_callee_candidates}/{result.contexts_measured}",
            f"{result.wall_time_s:.2f}",
        )
    out.print(table)

    if any(result.mode is AblationMode.RETRIEVAL_ONLY for result in suite.results):
        out.print(
            "\nmacro-F2 is the analyzer-only score in every retrieval-only row: no model "
            "read either context, so nothing downstream of retrieval could move. The "
            "column that answers a retrieval-only grid is evidence coverage."
        )

    out.print(f"\ncoverage: {_coverage_line(suite)}")
    out.print(
        f"detection: structural retrieval finds more than the flat window — "
        f"{_verdict(suite.structural_retrieval_earns_itself())}"
    )


def _coverage_line(suite: AblationSuite) -> str:
    """The retrieval comparison, with the numbers and the tie spelled out.

    A tie is reported as a tie. ``structural_retrieval_covers_more`` is a
    strict ``>`` because a control that merely matched has not been beaten —
    but rendering that as a flat "no" would read as a loss, and on a corpus
    whose files are shorter than the window a tie is the expected result and
    says nothing about either variant.
    """
    base, control = suite.baseline, suite.control
    if base is None or control is None:
        return "not measured — the flat-window control has not been run"
    if base.evidence_coverage is None or control.evidence_coverage is None:
        return "not measured — no ground-truth coverage was recorded"

    structural, flat = base.evidence_coverage, control.evidence_coverage
    cost = (
        f"{control.tokens / base.tokens:.1f}x the tokens"
        if base.tokens
        else f"{control.tokens} tokens against nothing measured"
    )
    if structural > flat:
        return (
            f"structural retrieves more of the decisive code ({structural:.4f} against "
            f"{flat:.4f}), and the control spends {cost}"
        )
    if structural < flat:
        return (
            f"the flat window retrieves more of the decisive code ({flat:.4f} against "
            f"{structural:.4f}), spending {cost}"
        )
    return (
        f"both variants retrieve the same share of the decisive code ({structural:.4f}), "
        f"and the control spends {cost}. A tie on a corpus whose files are shorter than "
        f"the window is expected and distinguishes nothing"
    )


def _verdict(answer: bool | None) -> str:
    """Three answers, never two. ``None`` is a result, not a missing one."""
    if answer is None:
        return "not measured"
    return "yes" if answer else "no"
