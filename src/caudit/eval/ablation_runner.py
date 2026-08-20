"""Running an ablation grid against a real suite.

:mod:`caudit.eval.ablation` builds the grid and holds the rules about what a
grid may contain. This is the half that makes a row a *measurement*: it turns
one :class:`~caudit.eval.ablation.AblationConfig` into a configured run of the
same pipeline ``caudit scan`` uses, and reports what moved.

There are two modes, and the difference between them is the whole reason this
module is careful.

**Detection** puts a model in the loop and scores the result. It answers the
question the ablation is really about — does this factor change what the tool
finds — and it needs consent and a provider.

**Retrieval-only** stops after expansion. It needs no key, no consent and no
network, which is what makes the flat-window control runnable on a machine
that has none of those. What it measures is narrower and stated as such: how
much of the code that decides each case was put on the page, and what that
cost in tokens. A retrieval-only row's ``macro_f2`` is the analyzer-only score
and is identical in every row of the grid, because no model read either
context; :class:`~caudit.eval.ablation.AblationSuite` refuses to draw a
detection verdict from rows measured this way.

Two rules carried from part 13's invariants:

* **A case that cannot be indexed is excluded with a reason**, from every row
  of the grid rather than from the one that noticed. Comparing variants over
  different case sets would report a difference between two corpora as a
  difference between two retrieval strategies.
* **The control is measured by the same code as the baseline.** The variant is
  a configuration value read by :func:`caudit.retrieval.expand`; there is no
  second expansion path here for the control to take, and so no way for the
  comparison to be against something the tool does not actually do.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter

from caudit.application.evaluation import run_suite
from caudit.application.pipeline import sort_candidates
from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.eval.ablation import AblationConfig, AblationMode, AblationResult
from caudit.eval.adjudicated import AdjudicatedSource, CompileCommandsFor
from caudit.eval.baseline import CandidateSource
from caudit.eval.case import BenchmarkCase, BenchmarkSuite
from caudit.evidence.store import SourceStore
from caudit.index.store import Index, build_index
from caudit.intake import load_scan_plan
from caudit.llm.service import ConsentDecision, LLMProvider
from caudit.logging import get_logger
from caudit.model.candidate import Candidate
from caudit.model.finding import LimitationKind, ReviewReason
from caudit.retrieval.paths import CALLEE_LOWER_BOUND
from caudit.retrieval.policy import ExpansionPolicy
from caudit.retrieval.service import RunLedger, expand

__all__ = [
    "ExcludedCase",
    "RetrievalMeasurement",
    "SuiteScorer",
    "measure_retrieval",
]

log = get_logger(__name__)


@dataclass(frozen=True)
class ExcludedCase:
    """A case no row could measure, and why.

    Recorded rather than dropped. A grid that quietly skips the cases it could
    not index reports a comparison between two configurations over whatever
    subset each happened to manage.
    """

    case_id: str
    reason: str


@dataclass(frozen=True)
class RetrievalMeasurement:
    """What expansion put on the page, over one suite, under one policy."""

    #: Ground-truth vulnerable lines that landed inside some retrieved unit.
    truths_covered: int = 0
    #: Ground-truth vulnerable lines in the cases that were measured.
    truths_total: int = 0
    #: Candidate contexts expanded.
    contexts: int = 0
    #: Estimated context tokens across those contexts. An estimate of what
    #: *would* be sent, not billed usage — nothing was sent.
    tokens: int = 0
    excluded: tuple[ExcludedCase, ...] = ()
    #: Candidates the run budget ran out before reaching.
    starved: int = 0
    #: Candidates whose primary set alone exceeded the per-candidate ceiling,
    #: which emits no context at all rather than half a function.
    budget_exceeded: int = 0
    #: Candidates whose callee traversal stopped at a function pointer. Callee
    #: direction only — see :data:`caudit.retrieval.paths.CALLEE_LOWER_BOUND`.
    indirect_callees: int = 0

    @property
    def coverage(self) -> float | None:
        """Share of decisive lines retrieved, or ``None`` if nothing was measured.

        ``None`` rather than ``0.0`` for an empty denominator: a suite in which
        nothing could be measured and a suite in which retrieval found nothing
        are opposite results, and averaging them into the same number is how a
        broken harness reads as a broken tool.
        """
        if self.truths_total == 0:
            return None
        return self.truths_covered / self.truths_total


def _index_case(case: BenchmarkCase, database: Path, config: Config) -> Index:
    """Index one benchmark case, with the coverage floor relaxed.

    The same relaxation :class:`~caudit.eval.adjudicated.AdjudicatedSource`
    makes, and for the same reason: the floor is set for repositories, and a
    case is a handful of files.
    """
    merged = config.model_dump()
    merged["intake"] = {**merged["intake"], "allow_partial_coverage": True}
    harness = Config.model_validate(merged)
    plan = load_scan_plan(case.root, database, harness, git_runner=lambda _args, _cwd: None)
    return build_index(plan, harness)


def _covered(line: int, path: str, contexts_regions: Sequence[tuple[str, int, int]]) -> bool:
    return any(
        region_path == path and start <= line <= end for region_path, start, end in contexts_regions
    )


def measure_retrieval(
    cases: Sequence[BenchmarkCase],
    *,
    config: Config,
    source: CandidateSource,
    compile_commands: CompileCommandsFor,
    max_file_bytes: int = 2_000_000,
) -> RetrievalMeasurement:
    """Expand every candidate in every case and report what was retrieved.

    Coverage is measured per case over the union of every candidate's context:
    the question is whether the decisive lines were put in front of the model
    at all, not which candidate's expansion happened to reach them. A case that
    cannot be indexed contributes to neither the numerator nor the denominator
    and is named in ``excluded``.

    The index is built even for the ``flat_window`` control, which does not
    consult it. That is deliberate: the exclusion set has to be decided by the
    corpus rather than by the configuration, or the control would be scored
    over cases the baseline was excluded from and the comparison would be
    between two corpora wearing the names of two retrieval strategies.
    """
    policy = ExpansionPolicy.from_config(config)
    covered = total = contexts = tokens = 0
    starved = budget_exceeded = indirect_callees = 0
    excluded: list[ExcludedCase] = []

    # Asked once, before the loop: a suite with no way to materialize a database
    # excludes every case for the same reason, and saying so once per case in
    # the adapter's words keeps a harness gap from reading like a fact about
    # the corpus. Still an exclusion, never a raise -- coverage of `None` over a
    # fully excluded suite is the signal (T-13-20).
    no_database = (
        "no compilation database"
        if compile_commands.can_materialize
        else "the suite implements no materialize_compile_commands, so no case can be indexed"
    )

    for case in sorted(cases, key=lambda item: item.case_id):
        database = compile_commands(case)
        if database is None:
            excluded.append(ExcludedCase(case.case_id, no_database))
            continue
        try:
            index = _index_case(case, database, config)
        except CauditError as exc:
            excluded.append(ExcludedCase(case.case_id, f"could not be indexed: {exc}"))
            continue

        store = SourceStore(
            case.root, revision=f"fixture:{case.case_id}", max_file_bytes=max_file_bytes
        )
        candidates: list[Candidate] = list(source.candidates_for(case, store))
        ledger = RunLedger(budget=config.token_budget)
        regions: list[tuple[str, int, int]] = []

        for candidate in sort_candidates(candidates):
            if ledger.exhausted:
                ledger.starve(candidate.candidate_id)
                starved += 1
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
            contexts += 1
            tokens += context.total_tokens
            if context.review_reason is ReviewReason.CONTEXT_BUDGET_EXCEEDED:
                budget_exceeded += 1
            if any(
                limitation.kind is LimitationKind.UNRESOLVED_INDIRECT_CALL
                and CALLEE_LOWER_BOUND in limitation.detail
                for limitation in context.limitations
            ):
                indirect_callees += 1
            regions.extend(
                (str(unit.region.path), unit.region.start_line, unit.region.end_line)
                for unit in context.units
            )

        truths = [truth for truth in case.ground_truth if truth.variant == "vulnerable"]
        total += len(truths)
        covered += sum(1 for truth in truths if _covered(truth.line, str(truth.path), regions))

    return RetrievalMeasurement(
        truths_covered=covered,
        truths_total=total,
        contexts=contexts,
        tokens=tokens,
        excluded=tuple(excluded),
        starved=starved,
        budget_exceeded=budget_exceeded,
        indirect_callees=indirect_callees,
    )


@dataclass
class SuiteScorer:
    """Measures one ablation configuration against a benchmark suite.

    Injected into :func:`~caudit.eval.ablation.run_grid` as its ``Scorer``, so
    the grid's rules and the measurement stay separable and each is testable
    without the other.

    ``provider`` and ``consent`` decide the mode. Supplying neither is not a
    degraded detection run — it is a retrieval-only run, labelled as one, for
    the reasons in this module's docstring.
    """

    suite: BenchmarkSuite
    config: Config
    workspace: Path
    source: CandidateSource
    case_ids: Sequence[str] = ()
    provider: LLMProvider | None = None
    consent: ConsentDecision | None = None
    analyzers: Sequence[str] = ()
    policy_versions: Mapping[str, str] = field(default_factory=dict)
    #: Cases excluded, keyed by the configuration that could not measure them.
    #:
    #: Keyed rather than overwritten: this was a single tuple reassigned on
    #: every call, so a grid reported only its last configuration's exclusions
    #: and a case that failed under the baseline alone vanished from the record.
    #: The exclusion set is supposed to be decided by the corpus rather than by
    #: the configuration, and keeping them apart is how a run can show that it
    #: was.
    excluded_by_config: dict[str, tuple[ExcludedCase, ...]] = field(default_factory=dict)

    @property
    def excluded(self) -> tuple[ExcludedCase, ...]:
        """Every case excluded under any configuration, once each, sorted.

        The union rather than one row's view: a case only the control could not
        measure is still a case the grid did not score.
        """
        seen: dict[tuple[str, str], ExcludedCase] = {}
        for cases in self.excluded_by_config.values():
            for case in cases:
                seen.setdefault((case.case_id, case.reason), case)
        return tuple(sorted(seen.values(), key=lambda case: (case.case_id, case.reason)))

    @property
    def exclusions_agree(self) -> bool:
        """Whether every configuration excluded exactly the same case ids.

        When this is ``False`` the rows were scored over different corpora, and
        a delta between them is not attributable to the factor that varied.
        """
        sets = {
            frozenset(case.case_id for case in cases) for cases in self.excluded_by_config.values()
        }
        return len(sets) <= 1

    @property
    def adjudicating(self) -> bool:
        """Whether this scorer will *try* to put a model in the loop.

        Distinct from the mode a row ends up with: trying and making no call is
        not a detection measurement, and only the row knows which happened.
        """
        return self.provider is not None and self.consent is not None

    def __call__(self, ablation: AblationConfig) -> AblationResult:
        effective = ablation.apply_to(self.config)
        cases = self._cases()
        started = perf_counter()

        retrieval = measure_retrieval(
            cases,
            config=effective,
            source=self.source,
            compile_commands=CompileCommandsFor(self.suite, self.workspace / ablation.name),
        )
        self.excluded_by_config[ablation.name] = retrieval.excluded

        adjudicator = None
        if self.provider is not None and self.consent is not None:
            adjudicator = AdjudicatedSource(
                config=effective,
                provider=self.provider,
                consent=self.consent,
                compile_commands=CompileCommandsFor(self.suite, self.workspace / ablation.name),
                analyzers=self.analyzers,
            )

        result = run_suite(
            self.suite,
            source=self.source,
            case_ids=[case.case_id for case in cases],
            max_file_bytes=effective.token_budget.max_file_bytes,
            is_baseline_run=adjudicator is None,
            adjudicator=adjudicator,
        )
        # Billed usage where a model answered, estimated context cost where
        # none did. Two different quantities, which is why the mode is on the
        # row beside them.
        tokens = adjudicator.account.total_tokens if adjudicator is not None else retrieval.tokens
        calls = adjudicator.account.calls if adjudicator is not None else 0
        # A row that intended to adjudicate and made no call did not measure
        # detection, whatever it intended. A missing key, an unreachable
        # provider and a cost ceiling that bound immediately all produce a grid
        # of provider failures that reads exactly like a model finding nothing,
        # and labelling that ``detection`` would put a verdict on it.
        mode = (
            AblationMode.DETECTION
            if adjudicator is not None and calls
            else AblationMode.RETRIEVAL_ONLY
        )
        return AblationResult(
            config=ablation,
            macro_f2=result.metrics.macro_f2,
            evidence_validity_rate=result.metrics.evidence_validity_rate,
            citation_resolution_rate=result.metrics.citation_resolution_rate,
            confirmed_count=result.metrics.confirmed_count,
            review_required_count=result.metrics.review_required_count,
            tokens=tokens,
            wall_time_s=perf_counter() - started,
            policy_versions=dict(sorted(self.policy_versions.items())),
            mode=mode,
            adjudication_calls=calls,
            evidence_coverage=retrieval.coverage,
            contexts_measured=retrieval.contexts,
            starved_candidates=retrieval.starved,
            budget_exceeded_candidates=retrieval.budget_exceeded,
            indirect_callee_candidates=retrieval.indirect_callees,
        )

    def _cases(self) -> list[BenchmarkCase]:
        wanted = set(self.case_ids)
        return sorted(
            (case for case in self.suite.cases() if not wanted or case.case_id in wanted),
            key=lambda case: case.case_id,
        )
