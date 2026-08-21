"""Run a suite, score it, gate it, and write the artefacts.

Determinism is a requirement, not a nicety: two runs over the same suite must
produce identical metrics, or nothing measured here can be compared over
time. Cases are visited in sorted order, findings are sorted by id, and
nothing in the scoring path reads a clock or a random source.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from caudit.config.loader import Config
from caudit.errors import RegionError
from caudit.eval.baseline import (
    CandidateSource,
    ClangBaselineSource,
    RecordedCandidateSource,
    promote_candidate,
)
from caudit.eval.case import BenchmarkCase, BenchmarkSuite
from caudit.eval.compare import CostSummary, RunReport
from caudit.eval.experiment import ExperimentCondition, build_experiment_manifest
from caudit.eval.gates import (
    KNOWN_PRODUCER_TOOLS,
    GateResult,
    evaluate_gates,
    gates_passed,
)
from caudit.eval.identity import candidate_set_hash, corpus_hash
from caudit.eval.matching import MatchingPolicy, default_policy
from caudit.eval.metrics import Metrics, compute_metrics
from caudit.eval.trace import TraceWriter
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import Citation, CitationResolver, Resolution
from caudit.evidence.store import SourceStore
from caudit.model.candidate import Candidate
from caudit.model.finding import Finding

__all__ = ["EvalResult", "FindingSource", "run_suite", "select_cases", "write_metrics"]


@runtime_checkable
class FindingSource(Protocol):
    """Anything that turns one case's candidates into findings.

    The analyzer-only path is a function call rather than an implementation of
    this, deliberately: promotion has no state, and giving it an object would
    suggest it might.
    """

    def findings_for(
        self, case: BenchmarkCase, candidates: Sequence[Candidate], store: SourceStore
    ) -> Sequence[Finding]: ...


@dataclass(frozen=True)
class EvalResult:
    """Everything one evaluation run produced."""

    metrics: Metrics
    gates: tuple[GateResult, ...]
    findings_by_case: Mapping[str, tuple[Finding, ...]]
    resolutions: tuple[Resolution, ...]
    tool_versions: Mapping[str, str]
    cases: tuple[BenchmarkCase, ...] = ()
    candidates_by_case: Mapping[str, tuple[Candidate, ...]] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return gates_passed(self.gates)


def select_cases(suite: BenchmarkSuite, case_ids: Sequence[str]) -> list[BenchmarkCase]:
    wanted = set(case_ids)
    cases = [case for case in suite.cases() if not wanted or case.case_id in wanted]
    missing = wanted - {case.case_id for case in cases}
    if missing:
        raise KeyError(f"unknown case ids for suite {suite.name}: {sorted(missing)}")
    return sorted(cases, key=lambda case: case.case_id)


def run_suite(
    suite: BenchmarkSuite,
    *,
    source: CandidateSource | None = None,
    policy: MatchingPolicy | None = None,
    case_ids: Sequence[str] = (),
    max_file_bytes: int = 2_000_000,
    trace: TraceWriter | None = None,
    baseline: Metrics | None = None,
    is_baseline_run: bool = True,
    extra_findings: Mapping[str, Sequence[Finding]] | None = None,
    adjudicator: FindingSource | None = None,
    known_tools: Iterable[str] = KNOWN_PRODUCER_TOOLS,
) -> EvalResult:
    """Score one suite with one candidate source.

    ``extra_findings`` injects additional findings into named cases. It exists
    for the adversarial tests, which have to be able to smuggle a fabricated
    claim into an otherwise clean run and watch the gate catch it.

    ``adjudicator`` replaces the analyzer-only promotion with part 12's
    pipeline, which is how ``--no-baseline`` is scored. Everything after it —
    the citation resolution, the matching, the metrics, the hard gates — is
    identical either way, because a comparison whose two sides were scored by
    different code measures the difference between the scorers.
    """
    candidate_source = source or RecordedCandidateSource()
    matching = policy or default_policy()
    cases = select_cases(suite, case_ids)

    findings_by_case: dict[str, tuple[Finding, ...]] = {}
    candidates_by_case: dict[str, tuple[Candidate, ...]] = {}
    resolutions: list[Resolution] = []

    for case in cases:
        store = SourceStore(
            case.root, revision=f"fixture:{case.case_id}", max_file_bytes=max_file_bytes
        )
        bundle = EvidenceBundle(store)
        candidates = list(candidate_source.candidates_for(case, store))
        candidates_by_case[case.case_id] = tuple(candidates)
        findings = (
            [promote_candidate(c, store=store) for c in candidates]
            if adjudicator is None
            else list(adjudicator.findings_for(case, candidates, store))
        )
        findings.extend(extra_findings.get(case.case_id, ()) if extra_findings else ())
        findings.sort(key=lambda f: (f.location.path, f.location.start_line, f.finding_id))
        findings_by_case[case.case_id] = tuple(findings)

        for finding in findings:
            for item in finding.evidence:
                # Only items the bundle actually issued are citable; adding
                # them here is what gives an invented id nothing to match.
                try:
                    bundle.add(item)
                except RegionError:
                    # The region cannot be read, so the bundle never issues an
                    # id for it and the citation below fails as unknown. That
                    # is the correct outcome, not something to paper over.
                    continue
        resolver = CitationResolver(store, bundle)
        for finding in findings:
            citations = [
                Citation.from_evidence(
                    item.evidence_id,
                    symbol=item.symbol.name if item.symbol else None,
                )
                for item in finding.evidence
            ]
            # The location is a region claim, not a symbol claim: the symbol
            # is verified through the evidence item whose region spans it.
            citations.append(Citation.from_region(finding.location))
            resolutions.extend(resolver.resolve_all(citations))

        if trace is not None:
            trace.write(
                "case_scored",
                case_id=case.case_id,
                candidates=len(candidates),
                findings=len(findings),
                confirmed=sum(1 for f in findings if f.is_confirmed),
                review_required=sum(1 for f in findings if not f.is_confirmed),
                lines_of_code=case.lines_of_code,
                analyzer_blind_spot=case.analyzer_blind_spot,
            )

    metrics = compute_metrics(
        suite=suite.name,
        cases=cases,
        findings_by_case=findings_by_case,
        resolutions=resolutions,
        policy=matching,
    )
    all_findings = [f for items in findings_by_case.values() for f in items]
    gates = tuple(
        evaluate_gates(
            metrics,
            all_findings,
            resolutions,
            baseline=baseline,
            is_baseline_run=is_baseline_run,
            known_tools=known_tools,
        )
    )

    if trace is not None:
        trace.write(
            "metrics",
            macro_f2=metrics.macro_f2,
            fp_per_kloc=metrics.fp_per_kloc,
            confirmed_count=metrics.confirmed_count,
            review_required_count=metrics.review_required_count,
            citation_resolution_rate=metrics.citation_resolution_rate,
            evidence_validity_rate=metrics.evidence_validity_rate,
        )
        for gate in gates:
            trace.write(
                "gate",
                name=gate.name,
                passed=gate.passed,
                observed=gate.observed,
                threshold=gate.threshold,
            )

    return EvalResult(
        metrics=metrics,
        gates=gates,
        findings_by_case=findings_by_case,
        resolutions=tuple(resolutions),
        tool_versions=dict(candidate_source.tool_versions()),
        cases=tuple(cases),
        candidates_by_case=candidates_by_case,
    )


def write_metrics(
    result: EvalResult,
    path: Path,
    *,
    policy_versions: Mapping[str, str] | None = None,
    cost: CostSummary | None = None,
    adjudicated: bool = False,
    config: Config | None = None,
    experiment_condition: ExperimentCondition | None = None,
    experiment_prompt_hashes: Mapping[str, str] | None = None,
    experiment_schema_hashes: Mapping[str, str] | None = None,
) -> Path:
    """Serialise the run as a :class:`~caudit.eval.compare.RunReport`.

    Sorted keys, so two runs diff cleanly. The three keyword arguments are what
    part 12 added: without them a later ``caudit compare`` cannot tell whether
    two files were produced under the same policies, and would difference two
    incomparable runs into a number that looks like a result.
    """
    experiment = None
    if config is not None:
        cases = result.cases
        identity = corpus_hash(cases)
        experiment = build_experiment_manifest(
            config=config,
            condition=experiment_condition
            or (
                ExperimentCondition.ADJUDICATED
                if adjudicated
                else ExperimentCondition.ANALYZER_CONTROL
            ),
            candidate_set_hash=candidate_set_hash(result.candidates_by_case),
            candidate_count=sum(len(items) for items in result.candidates_by_case.values()),
            corpus_hash=identity,
            corpus_revision="content:" + identity,
            analyzer_versions=result.tool_versions,
            policy_versions=policy_versions or {},
            truth_frame=result.metrics.truth_frame,
            prompt_hashes=experiment_prompt_hashes,
            schema_hashes=experiment_schema_hashes,
        )
    report = RunReport(
        metrics=result.metrics,
        gates=list(result.gates),
        tool_versions=dict(sorted(result.tool_versions.items())),
        policy_versions=dict(sorted((policy_versions or {}).items())),
        cost=cost or CostSummary(),
        scope=sorted(result.findings_by_case),
        adjudicated=adjudicated,
        experiment=experiment,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.loads(report.model_dump_json())
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def default_source(*, use_clang: bool = False) -> CandidateSource:
    """Where candidates come from. Recorded fixtures unless Clang is asked for.

    It deliberately no longer takes ``baseline``. Candidate *generation* is the
    same in both modes — the analyzers find what they find — and everything an
    adjudicated run adds happens afterwards, in the ``adjudicator`` that turns
    those candidates into findings. Keeping the two independent is what makes
    the comparison like-for-like: both sides start from the same candidates,
    so a delta cannot come from one side having seen more.
    """
    return ClangBaselineSource() if use_clang else RecordedCandidateSource()
