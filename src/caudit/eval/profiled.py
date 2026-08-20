"""Candidate generation for the benchmark, using the pass ``caudit scan`` uses.

:mod:`caudit.eval.adjudicated` already states the rule this module exists to
apply to the other half of the pipeline: *"it reuses part 12's pipeline rather
than growing a second one. If the harness adjudicated candidates differently
from ``caudit scan``, the number this produces would describe a tool nobody
ships."* Candidate generation had grown the second pipeline anyway.

:class:`~caudit.eval.baseline.ClangBaselineSource` is part 04's thin direct
invocation, written before part 07 existed. It shells out to ``clang-tidy``
with ``bugprone-*``, ``cert-*`` and ``clang-analyzer-*``, and it runs no
compiler diagnostics at all. Part 07's curated profile is a different ruleset
in both directions, and the difference is not academic — measured on the
committed mini suite with clang 18.1.3:

* ``-Wformat-security`` is in the profile and maps to CWE-134. It is the whole
  of the ``format-string-user-input`` case, the real scan finds it, and the
  part 04 source cannot: it enables no diagnostics. The baseline recorded a
  **miss** for a defect the shipped tool detects.
* ``security.insecureAPI.strcpy`` is the *only* member of that checker family
  the profile enables. The ``clang-analyzer-*`` glob pulls in the rest,
  including ``DeprecatedOrUnsafeBufferHandling``, which fires on every
  ``memset`` and ``memcpy``. The baseline recorded **false positives** the
  shipped tool never produces.

Both directions push the published number away from the truth about C Audit,
which is the "static-analyzer bias" risk the plan's traceability matrix names
against parts 04 and 07. So the clang-backed benchmark path runs
:func:`caudit.analyzers.generate_candidates` — the same function, the same
profile, the same normaliser, the same deduplication — and what it scores is
what a user gets.

``ClangBaselineSource`` is kept rather than deleted: it is the only candidate
source that needs no compilation database, which is what a suite whose adapter
cannot produce one still has. Choosing it is now an explicit fallback with a
recorded reason instead of the default nobody noticed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from caudit.analyzers.service import generate_candidates
from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.eval.adjudicated import CompileCommandsFor
from caudit.eval.case import BenchmarkCase
from caudit.evidence.store import SourceStore
from caudit.index.store import build_index
from caudit.intake import load_scan_plan
from caudit.logging import get_logger
from caudit.model.candidate import Candidate

__all__ = ["ProfiledCandidateSource"]

log = get_logger(__name__)


@dataclass
class ProfiledCandidateSource:
    """Runs the shipped analyzer pass over each case.

    Holds ``unanalysed`` for the same reason
    :class:`~caudit.eval.adjudicated.AdjudicatedSource` holds ``unindexed``: a
    case this could not run over contributes no candidates, which scores
    identically to a case that came back clean. The caller reports the list, so
    the difference stays visible in the run rather than only in the metrics,
    where it is invisible.
    """

    config: Config
    compile_commands: CompileCommandsFor
    out_dir: Path
    name: str = "clang-profile"
    _versions: dict[str, str] = field(default_factory=dict, init=False)
    #: Cases with no compilation database, or whose analysis raised. Scored as
    #: producing nothing, and named by the caller.
    unanalysed: list[str] = field(default_factory=list, init=False)

    def candidates_for(self, case: BenchmarkCase, _store: SourceStore) -> Sequence[Candidate]:
        # The store is part of the `CandidateSource` protocol because the
        # recorded source rebuilds regions through it. This pass does not need
        # it: `generate_candidates` builds its own from the scan plan, which is
        # the point — it is the scan's store, not the harness's.
        database = self.compile_commands(case)
        if database is None:
            self.unanalysed.append(case.case_id)
            log.warning("case %s has no compilation database; no analyzer ran", case.case_id)
            return ()

        try:
            plan = load_scan_plan(case.root, database, self._harness_config(), git_runner=_no_git)
            index = build_index(plan, self._harness_config())
            result = generate_candidates(
                plan,
                index,
                self._harness_config(),
                out_dir=self.out_dir / case.case_id,
            )
        except CauditError as exc:
            # Our own typed errors only. An unexpected exception is a bug, and
            # swallowing it here would turn a crash into a quietly empty case.
            self.unanalysed.append(case.case_id)
            log.warning("case %s could not be analysed (%s)", case.case_id, exc)
            return ()

        self._versions.update(result.tool_versions)
        return result.candidates

    def tool_versions(self) -> Mapping[str, str]:
        return dict(self._versions)

    def _harness_config(self) -> Config:
        """The caller's configuration with the coverage floor relaxed.

        Same reasoning as ``AdjudicatedSource._index``: a benchmark case is a
        handful of files described in full by its database, so the floor never
        binds on purpose — but it is set for repositories and can trip on a
        case whose variants compile separately. Relaxing it is a decision about
        the harness, so it does not touch the caller's configuration object.
        """
        merged = self.config.model_dump()
        merged["intake"] = {**merged["intake"], "allow_partial_coverage": True}
        return Config.model_validate(merged)


def _no_git(_args: Sequence[str], _cwd: Path) -> None:
    """Benchmark cases are not checkouts; there is no revision to resolve."""
    return None
