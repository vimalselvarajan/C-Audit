"""``caudit scan``, wired end to end.

Intake, index, candidates, expansion, adjudication, the gate, ranking, and the
three artifacts — one function, in the order the pipeline runs. Everything it
calls already exists and is tested; what lives here is the sequencing, the
decisions about what happens when a stage does not work, and the exit code.

Two rules shape it.

**The network is opt-in and the type says so.** No provider is constructed
unless consent was granted, so a run without consent cannot open a socket by
accident — there is nothing in the process that could. That path is byte-for-
byte the Milestone 1 report, which is what makes it a baseline rather than a
degraded version of the adjudicated run.

**A stage that fails does not take the report with it.** The index crashing,
the analyzers refusing to start, the provider going away mid-run: each is
recorded as a failed stage, contributes a limitation, marks the report partial,
and the run continues on what it already had. The alternative — a traceback and
no artifacts — throws away the work of every stage that did succeed, and tells
a user nothing about their code.

Console output is rendered by caudit.report.console. This module decides what
happens; the output adapter decides how it reads.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from caudit import __version__
from caudit.analyzers.service import AnalyzerResult, generate_candidates
from caudit.application.dry_run import write_prompts
from caudit.application.pipeline import (
    PipelineResult,
    Stage,
    StageLog,
    StageNote,
    adjudicate_candidates,
    promote_only,
)
from caudit.application.providers import gemini_provider_factory
from caudit.config.loader import Config
from caudit.evidence.store import SourceStore
from caudit.index.store import Index, build_index
from caudit.intake import load_scan_plan
from caudit.intake.plan import ScanPlan
from caudit.llm.service import (
    ConsentDecision,
    LLMProvider,
    RunAccount,
    consent_state,
    record_consent,
    response_cache,
)
from caudit.logging import get_logger
from caudit.model.finding import Limitation
from caudit.model.manifest import ModelRecord
from caudit.report.console import (
    render_candidates,
    render_consent,
    render_index,
    render_plan,
    render_prompts,
    render_report,
)
from caudit.report.service import ReportArtifacts, build_report, write_report
from caudit.status import ExitCode

__all__ = ["ScanResult", "run_scan"]

log = get_logger(__name__)


@dataclass(frozen=True)
class ScanResult:
    """Everything one ``caudit scan`` produced, and how it should exit."""

    artifacts: ReportArtifacts
    plan: ScanPlan
    index: Index
    analyzers: AnalyzerResult
    pipeline: PipelineResult
    stages: StageLog
    exit_code: ExitCode

    @property
    def partial(self) -> bool:
        return self.stages.partial


def run_scan(
    repository: Path,
    compile_commands: Path,
    config: Config,
    *,
    out: Path,
    console: Console,
    remember: bool = False,
    dry_run_prompts: bool = False,
    provider: LLMProvider | None = None,
    started_at: datetime | None = None,
) -> ScanResult:
    """Run the whole pipeline and write the three artifacts.

    ``provider`` is injectable so the end-to-end tests can drive the model
    stage from committed cassettes. It is never *constructed* here unless
    consent was granted, which is the difference between a test double and a
    hole in the consent rule.
    """
    began = started_at or datetime.now(UTC)
    stages = StageLog()

    with stages.timed(Stage.INTAKE):
        plan = load_scan_plan(repository, compile_commands, config)
    render_plan(plan, console, out_dir=out)

    # The fallback is built before the stage runs, so a failure inside it
    # leaves a real (empty) index behind rather than a ``None`` every later
    # stage would have to test for. An index that parsed nothing answers every
    # question with "not recorded", which is exactly what happened.
    index = Index(revision=plan.revision, repo_root=plan.repo_root)
    with stages.timed(Stage.INDEX, degrade=True) as note:
        index = build_index(plan, config, cache_dir=out / "index-cache")
        _note_index(note, index, plan)
    render_index(index, console, plan=plan)

    analyzers = AnalyzerResult()
    with stages.timed(Stage.CANDIDATES, degrade=True) as note:
        analyzers = generate_candidates(plan, index, config, out_dir=out / "analyzer-output")
        if analyzers.failed_runs:
            note.degraded(
                f"{len(analyzers.failed_runs)} analyzer run(s) did not complete, so the "
                "units they covered were not fully examined"
            )
        elif not analyzers.analyzers_that_ran:
            note.degraded(
                "no analyzer ran, so nothing in this report is a statement about the code"
            )
    render_candidates(analyzers, console, seen=[*plan.limitations, *index.limitations()])

    if remember:
        recorded = record_consent(plan.repo_root, caudit_version=__version__)
        console.print(f"\nRecorded cloud consent: {recorded}")
    consent = consent_state(config, plan.repo_root)

    extra: list[Limitation] = []
    if dry_run_prompts:
        with stages.timed(Stage.EXPANSION, degrade=True) as note:
            prompts = write_prompts(plan, index, analyzers, config, out_dir=out / "prompts")
            render_prompts(prompts, console)
            extra.extend(prompts.limitations)
            note.skipped("prompts were assembled and written; --dry-run-prompts transmits nothing")
        pipeline = promote_only(analyzers.candidates, _store(plan, config))
        models: list[ModelRecord] = []
        cost = 0.0
    else:
        render_consent(consent, console)
        pipeline, models, cost = _model_stages(
            plan, index, analyzers, config, consent, stages, out=out, provider=provider
        )
        if not consent.granted:
            extra.append(consent.as_limitation())
        extra.extend(pipeline.limitations)

    # Timed for the caller, but the record cannot appear in the manifest this
    # block builds — a stage cannot include its own duration in the file it is
    # writing. The manifest carries the stages that decided its *content*, and
    # rendering is not one of them.
    with stages.timed(Stage.REPORT):
        sections, manifest = build_report(
            plan,
            index,
            analyzers,
            config,
            started_at=began,
            findings=pipeline.findings,
            extra_limitations=[*extra, *stages.limitations()],
            models=models,
            stages=stages.records,
            total_cost_usd=cost,
        )
    artifacts = write_report(sections, manifest, out)
    render_report(artifacts, console)

    return ScanResult(
        artifacts=artifacts,
        plan=plan,
        index=index,
        analyzers=analyzers,
        pipeline=pipeline,
        stages=stages,
        exit_code=_scan_exit_code(artifacts, analyzers, partial=stages.partial),
    )


# ------------------------------------------------------------------ internals


def _scan_exit_code(
    artifacts: ReportArtifacts, result: AnalyzerResult, *, partial: bool = False
) -> ExitCode:
    """Translate completed scan state into the stable command status."""
    if not result.analyzers_that_ran:
        return ExitCode.ENVIRONMENT
    if artifacts.sections.confirmed_count:
        return ExitCode.FINDINGS
    if partial:
        return ExitCode.ENVIRONMENT
    return ExitCode.OK


def _store(plan: ScanPlan, config: Config) -> SourceStore:
    return SourceStore(
        plan.repo_root,
        revision=plan.revision,
        max_file_bytes=config.token_budget.max_file_bytes,
        exclude_globs=config.exclude_globs,
    )


def _note_index(note: StageNote, index: Index, plan: ScanPlan) -> None:
    """Record which units did not parse, without calling the stage degraded.

    A unit that will not parse is a hole in the symbol table, and it is already
    reported three times over: in ``coverage.translation_units_failed``, in a
    part 06 limitation naming the file and the first error, and in the report's
    coverage section. It is the index doing its job, not failing at it.

    Marking the run partial for it as well would fire the loudest marker in the
    output on almost every real repository — headers a compilation database
    does not describe, a resource directory that is not configured — and a
    warning that is always on is a warning nobody reads. Partial is reserved
    for a stage that did not do its job: one that raised, or one whose work
    disappeared without being recorded anywhere else.
    """
    failed = [unit for unit in index.units() if not unit.indexed]
    if failed:
        note.observe(
            f"{len(failed)} of {len(plan.units)} translation unit(s) did not parse: "
            + ", ".join(str(unit.file) for unit in failed[:5])
            + ("…" if len(failed) > 5 else "")
            + ". Symbols, call edges and types from those units are missing, so a "
            "citation into them cannot resolve. The gap is counted in coverage and "
            "named in this run's limitations"
        )


def _model_stages(
    plan: ScanPlan,
    index: Index,
    analyzers: AnalyzerResult,
    config: Config,
    consent: ConsentDecision,
    stages: StageLog,
    *,
    out: Path,
    provider: LLMProvider | None,
) -> tuple[PipelineResult, list[ModelRecord], float]:
    """Adjudication and the gate, or the reason neither ran.

    Without consent this returns the analyzer-only promotion and an empty
    model list, and the two stages are recorded as ``skipped`` rather than
    omitted — "no tier was consulted" is a fact about the run, and a manifest
    that simply had no row for it would not be saying anything.
    """
    store = _store(plan, config)
    if not consent.granted:
        for stage in (Stage.EXPANSION, Stage.ADJUDICATION, Stage.VERIFICATION):
            with stages.timed(stage) as note:
                note.skipped(
                    "cloud consent was not given, so no candidate was sent to a model and "
                    "this report is the deterministic analyzer baseline"
                )
        return promote_only(analyzers.candidates, store), [], 0.0

    if not analyzers.candidates:
        for stage in (Stage.EXPANSION, Stage.ADJUDICATION, Stage.VERIFICATION):
            with stages.timed(stage) as note:
                note.skipped("no candidate was generated, so there was nothing to adjudicate")
        return promote_only(analyzers.candidates, store), [], 0.0

    account = RunAccount(config=config)
    cache = response_cache(config, out)
    backend = provider if provider is not None else gemini_provider_factory(consent)
    pipeline = promote_only(analyzers.candidates, store)

    # Retrieval, the model, and the gate are one loop per candidate, so they
    # are timed as one span and reported as three stages carrying the same
    # outcome. Splitting the loop to time them separately would mean expanding
    # every candidate before asking about any of them, which is exactly the
    # shape the run-level token ledger exists to avoid.
    with stages.timed(Stage.ADJUDICATION, degrade=True) as note:
        pipeline = adjudicate_candidates(
            analyzers.candidates,
            index,
            store,
            config,
            provider=backend,
            consent=consent,
            analyzers=sorted(analyzers.analyzers_that_ran),
            account=account,
            cache=cache,
        )
        unanswered = sum(
            1
            for outcome in pipeline.outcomes
            if outcome.adjudication is None or not outcome.adjudication.answered
        )
        if unanswered:
            note.degraded(
                f"{unanswered} of {len(pipeline.outcomes)} candidate(s) were not answered "
                "by a model; each carries the reason and stays in the report on the "
                "analyzer's word"
            )
    return pipeline, account.records(), account.cost_usd()
