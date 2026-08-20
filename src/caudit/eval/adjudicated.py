"""Scoring a suite with the model in the loop.

``caudit eval --baseline`` measures the analyzers alone. This is the other
half: the same suite, the same matching policy, the same gates, but every
candidate goes through retrieval, adjudication and the verification gate before
it is scored. Differencing the two is what Milestone 2's exit checklist asks
for, and :mod:`caudit.eval.compare` is what does the differencing.

It reuses part 12's pipeline rather than growing a second one. If the harness
adjudicated candidates differently from ``caudit scan``, the number this
produces would describe a tool nobody ships.

Two honest limitations, both recorded rather than worked around:

* A case with no compilation database cannot be indexed, so it cannot be
  expanded or adjudicated. Those cases fall back to the analyzer-only
  promotion and say so, because dropping them would quietly improve the score
  by removing the cases the model could not help with.
* Nothing here invents a provider. Adjudicated evaluation needs consent and a
  backend, and the caller supplies both — which is also what lets a test drive
  it from committed cassettes with no socket and no key.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from caudit.application.pipeline import adjudicate_candidates, promote_only
from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.eval.case import BenchmarkCase
from caudit.evidence.store import SourceStore
from caudit.index.store import Index, build_index
from caudit.intake import load_scan_plan
from caudit.llm.service import ConsentDecision, LLMProvider, ResponseCache, RunAccount
from caudit.logging import get_logger
from caudit.model.candidate import Candidate
from caudit.model.finding import Finding

__all__ = ["AdjudicatedSource", "CompileCommandsFor"]

log = get_logger(__name__)


class CompileCommandsFor:
    """How to get a compilation database for one case.

    A protocol in spirit and a class in practice, because the mini suite
    materializes its database from a committed template with a
    ``${CASE_ROOT}`` placeholder and other adapters will not. Returning
    ``None`` means "this case cannot be indexed", which is a recorded
    limitation and never a silent skip.

    **Two different failures both return ``None``, and the caller is told
    which.** A suite that implements no ``materialize_compile_commands`` at all
    cannot produce a database for *any* case -- a gap in the adapter, which is
    ``JulietSuite`` today and is the mistake a new adapter makes once. A suite
    that has the method and fails on one case is reporting a fact about that
    case. Both are excluded with a reason rather than raising, because coverage
    of ``None`` over a fully excluded suite is already the loud signal
    (T-13-20); what :attr:`can_materialize` adds is a reason that names the
    right cause, so a harness gap does not read as a corpus property.
    """

    def __init__(self, suite: object, workspace: Path) -> None:
        self._suite = suite
        self._workspace = workspace

    @property
    def can_materialize(self) -> bool:
        """Whether the suite can produce a database for any case at all."""
        return getattr(self._suite, "materialize_compile_commands", None) is not None

    def __call__(self, case: BenchmarkCase) -> Path | None:
        if case.compile_commands is not None and case.compile_commands.is_file():
            return case.compile_commands
        materialize = getattr(self._suite, "materialize_compile_commands", None)
        if materialize is None:
            return None
        try:
            path: Path = materialize(case.case_id, self._workspace / case.case_id)
        except (OSError, FileNotFoundError):
            return None
        return path


@dataclass
class AdjudicatedSource:
    """Turns one case's candidates into findings, with a model in the middle.

    Holds the run-level account so token and cost totals accumulate across the
    whole suite rather than resetting per case — a per-case ledger would let a
    suite spend arbitrarily much while every individual case looked frugal.
    """

    config: Config
    provider: LLMProvider
    consent: ConsentDecision
    compile_commands: CompileCommandsFor
    analyzers: Sequence[str] = ()
    cache: ResponseCache | None = None
    account: RunAccount = field(init=False)
    #: Case ids that could not be indexed, and so were scored on the
    #: analyzer's word alone. Read by the caller and reported, never dropped.
    unindexed: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.account = RunAccount(config=self.config)

    def findings_for(
        self, case: BenchmarkCase, candidates: Sequence[Candidate], store: SourceStore
    ) -> list[Finding]:
        """Every candidate in one case, adjudicated and gated.

        Returns the analyzer-only promotion when the case cannot be indexed,
        so a case the model never saw still contributes its baseline result to
        the score instead of vanishing from it.
        """
        database = self.compile_commands(case)
        if database is None:
            self.unindexed.append(case.case_id)
            return promote_only(candidates, store).findings

        try:
            index = self._index(case, database)
        except CauditError as exc:
            log.warning("case %s could not be indexed (%s); scoring it on the analyzers", case, exc)
            self.unindexed.append(case.case_id)
            return promote_only(candidates, store).findings

        return adjudicate_candidates(
            candidates,
            index,
            store,
            self.config,
            provider=self.provider,
            consent=self.consent,
            analyzers=self.analyzers,
            account=self.account,
            cache=self.cache,
        ).findings

    def _index(self, case: BenchmarkCase, database: Path) -> Index:
        """Index one case, with the coverage floor relaxed.

        A benchmark case is a handful of files with a database describing all
        of them, so the floor never binds in practice — but it is set for
        repositories, and a case whose fixed and vulnerable variants are
        compiled separately can trip it. Relaxing it here is a decision about
        the harness, not about scanning, so it does not touch the caller's
        configuration.
        """
        merged = self.config.model_dump()
        merged["intake"] = {**merged["intake"], "allow_partial_coverage": True}
        harness = Config.model_validate(merged)
        plan = load_scan_plan(case.root, database, harness, git_runner=lambda _args, _cwd: None)
        return build_index(plan, harness)

    def tool_versions(self) -> Mapping[str, str]:
        """The models that answered, for the run report's tool list."""
        return {
            f"model:{record.tier}": record.model_id
            for record in self.account.records()
            if record.calls
        }
