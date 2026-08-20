"""Application service for consent-free prompt preview generation."""

from __future__ import annotations

from pathlib import Path

from caudit.analyzers.service import AnalyzerResult
from caudit.config.loader import Config
from caudit.evidence.store import SourceStore
from caudit.index.store import Index
from caudit.intake.plan import ScanPlan
from caudit.llm.service import DryRunReport
from caudit.model.finding import Limitation
from caudit.retrieval.policy import ExpansionPolicy
from caudit.retrieval.service import RunLedger, expand

__all__ = ["write_prompts"]


def write_prompts(
    plan: ScanPlan,
    index: Index,
    result: AnalyzerResult,
    config: Config,
    *,
    out_dir: Path,
) -> DryRunReport:
    """Assemble every prompt this scan would send, and write it to disk.

    Sends nothing, and needs no consent, because consent governs transmission
    and nothing here transmits. It runs the real assembly path — the same
    exclusion filtering, the same scrubbing, the same second check — so what
    lands in ``<out>/prompts`` is the request body, not an approximation of it.

    Expansion is charged against the run's token ledger for the same reason a
    real run is: a repository with ten thousand candidates should not be able
    to turn ``--dry-run-prompts`` into an unbounded retrieval job.
    """
    from caudit.llm.service import dry_run_prompts

    store = SourceStore(
        plan.repo_root,
        revision=plan.revision,
        max_file_bytes=config.token_budget.max_file_bytes,
        exclude_globs=config.exclude_globs,
    )
    policy = ExpansionPolicy.from_config(config)
    ledger = RunLedger(budget=config.token_budget)
    contexts = []
    starved: list[Limitation] = []
    for candidate in result.candidates:
        if ledger.exhausted:
            starved.append(ledger.starve(candidate.candidate_id))
            continue
        context = expand(
            candidate,
            index,
            store,
            policy,
            config.token_budget,
            allowance=ledger.allowance(),
        )
        ledger.charge(context.total_tokens)
        contexts.append(context)

    report = dry_run_prompts(contexts, config=config, out_dir=out_dir)
    report.limitations.extend(starved)
    return report
