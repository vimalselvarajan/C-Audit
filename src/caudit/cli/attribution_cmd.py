"""Execute the cumulative Track-A attribution conditions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from caudit.application.evaluation import EvalResult, run_suite, write_metrics
from caudit.application.providers import gemini_provider_factory
from caudit.cli.eval_cmd import (
    _policy_versions,
    candidate_source,
    refuse_unrecorded_cases,
    resolve_suite,
)
from caudit.config.loader import Config
from caudit.errors import UsageError
from caudit.eval.adjudicated import AdjudicatedSource, CompileCommandsFor
from caudit.eval.attribution import (
    AttributionMatrix,
    AttributionStage,
    build_attribution_matrix,
    write_attribution_matrix,
)
from caudit.eval.compare import CostSummary, RunReport, load_run_report
from caudit.eval.experiment import ExperimentCondition
from caudit.eval.gates import KNOWN_PRODUCER_TOOLS, model_producer_tools
from caudit.eval.naive import (
    NaiveControlMode,
    NaiveFindingSource,
    naive_prompt_hash,
    naive_schema_hash,
)
from caudit.llm.provider import LLMProvider
from caudit.llm.service import consent_state, response_cache

__all__ = ["AttributionRun", "render_attribution", "run_attribution"]


@dataclass(frozen=True)
class AttributionRun:
    matrix: AttributionMatrix
    matrix_path: Path
    reports: dict[AttributionStage, Path]

    @property
    def passed(self) -> bool:
        return all(
            load_run_report(path).passed
            for stage, path in self.reports.items()
            if stage is not AttributionStage.A0
        )


def run_attribution(
    *,
    config: Config,
    suite: str,
    out_dir: Path,
    through: AttributionStage = AttributionStage.A5,
    case_ids: tuple[str, ...] = (),
    use_clang: bool = False,
    provider: LLMProvider | None = None,
    console: Console | None = None,
) -> AttributionRun:
    """Measure A0 through the selected implemented condition on identical candidates."""

    if through in {AttributionStage.A6, AttributionStage.A7}:
        raise UsageError(
            f"{through} is predeclared but not implemented",
            hint=(
                "Run through A5. A6 evidence navigation and A7 are deliberately sequenced "
                "after the first six strategic change sets and remain deferred in the matrix."
            ),
        )
    benchmark = resolve_suite(suite)
    source = candidate_source(config, benchmark, out_dir, use_clang=use_clang)
    refuse_unrecorded_cases(source, benchmark, case_ids)
    selected = list(AttributionStage)[: list(AttributionStage).index(through) + 1]

    consent = consent_state(config)
    backend = provider
    if len(selected) > 1:
        if not consent.granted:
            raise UsageError(
                "Track-A model conditions transmit source and require explicit cloud consent",
                hint="Set cloud_consent=true (or use the CLI's --consent-cloud flag).",
            )
        backend = backend or gemini_provider_factory(consent)
    out_dir.mkdir(parents=True, exist_ok=True)

    reports: dict[AttributionStage, tuple[Path, RunReport]] = {}
    written: dict[AttributionStage, Path] = {}
    baseline: EvalResult | None = None
    for stage in selected:
        stage_dir = out_dir / stage.lower()
        stage_dir.mkdir(parents=True, exist_ok=True)
        stage_config = _stage_config(config, stage)
        cost_source: object | None = None
        prompt_hashes = None
        schema_hashes = None

        if stage is AttributionStage.A0:
            result = run_suite(
                benchmark,
                source=source,
                case_ids=case_ids,
                max_file_bytes=config.token_budget.max_file_bytes,
                is_baseline_run=True,
            )
            baseline = result
        elif stage in {AttributionStage.A1, AttributionStage.A2}:
            assert backend is not None
            mode = (
                NaiveControlMode.UNSTRUCTURED
                if stage is AttributionStage.A1
                else NaiveControlMode.STRUCTURED
            )
            naive = NaiveFindingSource(
                config=stage_config,
                provider=backend,
                mode=mode,
                cache=(
                    response_cache(stage_config, stage_dir)
                    if mode is NaiveControlMode.STRUCTURED
                    else None
                ),
            )
            cost_source = naive
            prompt_hashes = {"naive_fixed_window": naive_prompt_hash(mode)}
            schema_hashes = {"naive_verdict": naive_schema_hash(mode)}
            result = run_suite(
                benchmark,
                source=source,
                case_ids=case_ids,
                max_file_bytes=config.token_budget.max_file_bytes,
                baseline=baseline.metrics if baseline is not None else None,
                is_baseline_run=False,
                adjudicator=naive,
                known_tools=KNOWN_PRODUCER_TOOLS | model_producer_tools(stage_config),
            )
        else:
            assert backend is not None
            full = AdjudicatedSource(
                config=stage_config,
                provider=backend,
                consent=consent,
                compile_commands=CompileCommandsFor(benchmark, stage_dir / "compile-commands"),
                analyzers=sorted(KNOWN_PRODUCER_TOOLS),
                cache=response_cache(stage_config, stage_dir),
                checkpoint_dir=stage_dir / "adjudication-checkpoints",
                verification_enabled=stage is not AttributionStage.A3,
            )
            cost_source = full
            result = run_suite(
                benchmark,
                source=source,
                case_ids=case_ids,
                max_file_bytes=config.token_budget.max_file_bytes,
                baseline=baseline.metrics if baseline is not None else None,
                is_baseline_run=False,
                adjudicator=full,
                known_tools=KNOWN_PRODUCER_TOOLS | model_producer_tools(stage_config),
            )

        report_path = write_metrics(
            result,
            stage_dir / f"metrics-{benchmark.name}-{stage.lower()}.json",
            policy_versions=_policy_versions(stage_config),
            cost=_source_cost(cost_source),
            adjudicated=stage is not AttributionStage.A0,
            config=stage_config,
            experiment_condition=ExperimentCondition(f"attribution_{stage.lower()}"),
            experiment_prompt_hashes=prompt_hashes,
            experiment_schema_hashes=schema_hashes,
        )
        written[stage] = report_path
        reports[stage] = (report_path.relative_to(out_dir), load_run_report(report_path))

    policy = config.llm.model_policy.adjudication
    matrix = build_attribution_matrix(
        suite=benchmark.name,
        reports=reports,
        model_id=config.models.adjudication,
        thinking_level=str(policy.thinking_level),
        max_output_tokens=policy.max_output_tokens,
    )
    matrix_path = write_attribution_matrix(matrix, out_dir / f"attribution-{benchmark.name}.json")
    if console is not None:
        render_attribution(matrix, console)
        console.print(f"\nattribution matrix: {matrix_path}")
    return AttributionRun(matrix=matrix, matrix_path=matrix_path, reports=written)


def _stage_config(config: Config, stage: AttributionStage) -> Config:
    if stage not in {AttributionStage.A3, AttributionStage.A4}:
        return config
    payload = config.model_dump(mode="json")
    payload["llm"] = {
        **payload["llm"],
        "triage_enabled": False,
        "allow_escalation": False,
    }
    return Config.model_validate(payload)


def _source_cost(source: object | None) -> CostSummary:
    account = getattr(source, "account", None)
    if account is None:
        return CostSummary()
    return CostSummary(
        calls=account.calls,
        input_tokens=sum(item.usage.input_tokens for item in account.accounts.values()),
        output_tokens=sum(item.usage.output_tokens for item in account.accounts.values()),
        thinking_tokens=sum(item.usage.thinking_tokens for item in account.accounts.values()),
        cached_input_tokens=sum(
            item.usage.cached_input_tokens for item in account.accounts.values()
        ),
        tool_use_tokens=sum(item.usage.tool_use_tokens for item in account.accounts.values()),
        provider_total_tokens=account.total_tokens,
        retry_count=account.retries,
        usd=account.cost_usd(),
    )


def render_attribution(matrix: AttributionMatrix, console: Console) -> None:
    table = Table(title=f"Track A attribution — {matrix.suite}")
    for column in ("stage", "status", "precision", "recall", "F2", "calls", "capability"):
        table.add_column(column)
    for row in matrix.rows:
        table.add_row(
            str(row.stage),
            str(row.status),
            "—" if row.precision is None else f"{row.precision:.4f}",
            "—" if row.recall is None else f"{row.recall:.4f}",
            "—" if row.macro_f2 is None else f"{row.macro_f2:.4f}",
            str(row.cost.calls),
            row.capabilities[-1],
        )
    console.print(table)
