"""Candidate generation (part 07).

Runs the deterministic analyzers over the scan plan and turns three
heterogeneous outputs into one ``Candidate`` stream: Clang compile
diagnostics, the Clang Static Analyzer, and a curated ``clang-tidy`` profile.

Nothing in this package decides whether something is a real vulnerability.
The spec's position is that analyzers generate candidates, not verdicts;
adjudication is part 10 and the evidence gate is part 11.

Four invariants hold across everything below:

* **Dedup never drops a producer.** Merging unions provenance.
* **The analyzer's own text is preserved verbatim** beside the normalized form.
* **A crashed, timed-out, or missing analyzer is a recorded limitation**, never
  an empty result read as a clean unit.
* **No candidate is discarded for being unmapped.** A rule with no CWE
  produces a candidate with none, routed to review.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from caudit.analyzers.csa import CsaAnalyzer, available_checkers
from caudit.analyzers.dedup import merge_candidates, sort_candidates
from caudit.analyzers.diagnostics import DiagnosticsAnalyzer
from caudit.analyzers.normalize import Normalizer, RawDiagnostic, RawNote
from caudit.analyzers.profile import CheckProfile, ProfileError, load_profile
from caudit.analyzers.runner import (
    Analyzer,
    AnalyzerRun,
    RunStatus,
    Subprocess,
    checkers_unavailable,
    run_command,
    run_units,
    tool_unavailable,
)
from caudit.analyzers.tidy import TidyAnalyzer
from caudit.config.loader import Config
from caudit.config.toolchain import parse_version
from caudit.evidence.store import SourceStore
from caudit.index.store import Index
from caudit.intake.plan import ScanPlan
from caudit.logging import get_logger
from caudit.model.candidate import Candidate
from caudit.model.finding import Limitation, LimitationKind

__all__ = [
    "Analyzer",
    "AnalyzerResult",
    "AnalyzerRun",
    "CheckProfile",
    "CsaAnalyzer",
    "DiagnosticsAnalyzer",
    "Normalizer",
    "ProfileError",
    "RawDiagnostic",
    "RawNote",
    "RunStatus",
    "TidyAnalyzer",
    "build_analyzers",
    "generate_candidates",
    "load_profile",
    "merge_candidates",
    "sort_candidates",
]

log = get_logger(__name__)


class AnalyzerResult(BaseModel):
    """Everything one candidate-generation pass produced.

    ``runs`` is kept beside ``candidates`` on purpose: a report that lists
    candidates without listing which analyzers ran, on which units, and how
    they ended cannot distinguish a clean repository from an unanalysed one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    runs: list[AnalyzerRun] = Field(default_factory=list)
    candidates: list[Candidate] = Field(default_factory=list)
    limitations: list[Limitation] = Field(default_factory=list)
    profile_version: str | None = None

    @property
    def tool_versions(self) -> dict[str, str]:
        """``{tool name: version}`` for every analyzer that actually ran."""
        return {run.tool_name: run.tool_version for run in self.runs if run.status.produced_output}

    @property
    def analyzers_that_ran(self) -> set[str]:
        return {run.tool_name for run in self.runs if run.status.produced_output}

    @property
    def units_analysed(self) -> set[str]:
        return {str(run.unit) for run in self.runs if run.status.produced_output}

    @property
    def failed_runs(self) -> list[AnalyzerRun]:
        return [run for run in self.runs if run.status.is_failure]

    def describe(self) -> str:
        return (
            f"{len(self.candidates)} candidate(s) from {len(self.analyzers_that_ran)} "
            f"analyzer(s) over {len(self.units_analysed)} translation unit(s); "
            f"{len(self.failed_runs)} run(s) did not complete"
        )


def build_analyzers(
    *,
    profile: CheckProfile,
    normalizer: Normalizer,
    config: Config,
    subprocess_runner: Subprocess | None = None,
) -> tuple[list[Analyzer], list[Limitation]]:
    """The analyzers this machine can actually run, and what it cannot.

    A missing binary is a limitation and an empty analyzer list, never a
    substitute analyzer and never silence. The versions are probed once here
    rather than per unit, but each run still records the version it used, so an
    exotic setup that hits two toolchains stays visible in the manifest.
    """
    settings = config.analyzers
    limitations: list[Limitation] = []
    analyzers: list[Analyzer] = []

    clang_version = _tool_version(settings.clang, subprocess_runner=subprocess_runner)
    tidy_version = _tool_version(settings.clang_tidy, subprocess_runner=subprocess_runner)

    if settings.enable_diagnostics:
        if clang_version is None:
            limitations.append(tool_unavailable("clang", settings.clang))
        else:
            analyzers.append(
                DiagnosticsAnalyzer(
                    profile=profile,
                    normalizer=normalizer,
                    clang=settings.clang,
                    tool_version=clang_version,
                    subprocess_runner=subprocess_runner,
                )
            )

    if settings.enable_csa:
        if clang_version is None:
            limitations.append(tool_unavailable("clang-static-analyzer", settings.clang))
        else:
            checkers, missing = _usable_checkers(
                profile, settings.clang, subprocess_runner=subprocess_runner
            )
            if missing:
                limitations.append(checkers_unavailable("clang", missing))
            analyzers.append(
                CsaAnalyzer(
                    profile=profile,
                    normalizer=normalizer,
                    clang=settings.clang,
                    tool_version=clang_version,
                    checkers=checkers,
                    subprocess_runner=subprocess_runner,
                )
            )

    if settings.enable_tidy:
        if tidy_version is None:
            limitations.append(tool_unavailable("clang-tidy", settings.clang_tidy))
        else:
            analyzers.append(
                TidyAnalyzer(
                    profile=profile,
                    normalizer=normalizer,
                    clang_tidy=settings.clang_tidy,
                    tool_version=tidy_version,
                    subprocess_runner=subprocess_runner,
                )
            )

    return analyzers, limitations


def generate_candidates(
    plan: ScanPlan,
    index: Index,
    config: Config,
    *,
    out_dir: Path | None = None,
    profile: CheckProfile | None = None,
    analyzers: Sequence[Analyzer] | None = None,
    subprocess_runner: Subprocess | None = None,
) -> AnalyzerResult:
    """Run the analyzers over the plan and return one merged candidate stream.

    Beyond the plan's three arguments this takes keyword-only extensions:
    ``out_dir`` for the retained raw output, and ``profile``, ``analyzers``,
    and ``subprocess_runner`` for injection, which is what lets the default
    test suite exercise the whole pass with no compiler installed.

    The result is deterministic. Runs are collected in ``(unit, analyzer)``
    order regardless of which finished first, candidates are sorted by a total
    key before merging, and merging is a greedy pass over that order.
    """
    settings = config.analyzers
    resolved_profile = profile or load_profile(settings.profile)
    # Absolute, always. Every analyzer runs with ``cwd=unit.directory`` -- the
    # scanned project's build directory, not ours -- and two of them are handed
    # this path to write to: clang-tidy's ``--export-fixes`` and the static
    # analyzer's ``-o``. A relative path resolves against *their* cwd, where it
    # does not exist, so the output goes nowhere. The two failures are not
    # equally loud, which is what made this worth a comment: clang-tidy calls it
    # an error and exits non-zero, so the run is recorded as failed and the
    # report is marked partial, while the static analyzer calls it a warning and
    # exits 0 -- a completed run that produced no results and reported no
    # reason. `caudit scan --out caudit-report`, the documented default, is
    # relative, so this silently emptied the static analyzer on every default
    # invocation. No test caught it because they all pass an absolute tmp_path.
    directory = (out_dir or Path(settings.raw_output_dir or ".caudit-analyzer-output")).resolve()
    store = SourceStore(
        plan.repo_root,
        revision=plan.revision,
        max_file_bytes=config.token_budget.max_file_bytes,
        exclude_globs=config.exclude_globs,
    )
    normalizer = Normalizer(
        store=store, profile=resolved_profile, index=index, repo_root=plan.repo_root
    )

    limitations: list[Limitation] = []
    if analyzers is None:
        selected, unavailable = build_analyzers(
            profile=resolved_profile,
            normalizer=normalizer,
            config=config,
            subprocess_runner=subprocess_runner,
        )
        limitations.extend(unavailable)
    else:
        selected = list(analyzers)

    if not selected:
        limitations.append(_nothing_ran(plan))
        return AnalyzerResult(
            runs=[],
            candidates=[],
            limitations=_dedupe(limitations),
            profile_version=resolved_profile.version,
        )

    runs = run_units(
        selected,
        plan.units,
        out_dir=directory,
        timeout_s=settings.per_unit_timeout_seconds,
        jobs=settings.jobs,
    )
    by_producer = {analyzer.name: analyzer for analyzer in selected}

    candidates: list[Candidate] = []
    for run in runs:
        limitation = run.limitation()
        if limitation is not None:
            limitations.append(limitation)
        analyzer = by_producer.get(run.analyzer)
        if analyzer is not None and run.status.produced_output:
            candidates.extend(analyzer.parse(run))

    if normalizer.stats.outside_repo:
        limitations.append(_outside_repo(normalizer))

    merged = merge_candidates(candidates)
    result = AnalyzerResult(
        runs=runs,
        candidates=merged,
        limitations=_dedupe(limitations),
        profile_version=resolved_profile.version,
    )
    log.info("candidate generation with %s: %s", resolved_profile.describe(), result.describe())
    return result


# ---------------------------------------------------------------- internals


def _tool_version(binary: str, *, subprocess_runner: Subprocess | None) -> str | None:
    """The tool's own version banner, or ``None`` when it is not installed.

    ``None`` and ``"unknown"`` are different answers: the first means nothing
    ran, the second means it ran and would not say which version it was. Only
    the first suppresses an analyzer.
    """
    if subprocess_runner is None and shutil.which(binary) is None:
        return None
    result = run_command([binary, "--version"], timeout_s=30.0, subprocess_runner=subprocess_runner)
    if result.status is RunStatus.TOOL_MISSING:
        return None
    return parse_version(result.output) or "unknown"


def _usable_checkers(
    profile: CheckProfile, clang: str, *, subprocess_runner: Subprocess | None
) -> tuple[list[str], list[str]]:
    """Profile checkers this Clang has, and the ones it does not.

    An unknown checker id makes Clang refuse the whole translation unit, so a
    profile pinned to one LLVM release would otherwise fail every unit on
    another. When the probe itself cannot answer, the profile is used unchanged
    — a failed probe is not evidence that a checker is absent.
    """
    wanted = profile.csa_checkers()
    known = available_checkers(clang, subprocess_runner=subprocess_runner)
    if known is None:
        log.debug("clang would not list its checkers; using the profile unfiltered")
        return wanted, []
    usable = [checker for checker in wanted if checker in known]
    return usable, [checker for checker in wanted if checker not in known]


def _nothing_ran(plan: ScanPlan) -> Limitation:
    """The loudest limitation in the package: no analyzer ran at all."""
    return Limitation(
        kind=LimitationKind.TOOLCHAIN_UNAVAILABLE,
        detail=(
            f"no analyzer ran over any of the {len(plan.units)} selected translation "
            "unit(s), so this run found nothing because it did not look. Install the "
            "Clang toolchain (caudit doctor names what is missing; my_docs/guides/setup.md has "
            "the commands) and scan again"
        ),
        affects=None,
    )


def _outside_repo(normalizer: Normalizer) -> Limitation:
    """Diagnostics whose location is not in the scanned tree."""
    examples = ", ".join(sorted(normalizer.stats.paths_outside_repo)[:3])
    return Limitation(
        kind=LimitationKind.EXCLUDED_BY_FILTER,
        detail=(
            f"{normalizer.stats.outside_repo} diagnostic(s) pointed outside the "
            f"repository root and produced no candidate (for example: {examples}). "
            "A system or build-directory header is not part of the scanned revision "
            "and nothing citable can be built from it"
        ),
        affects=None,
    )


def _dedupe(limitations: Sequence[Limitation]) -> list[Limitation]:
    """Stable order, no repeats, so two runs serialize identically."""
    unique = {(str(item.kind), item.affects or "", item.detail): item for item in limitations}
    return [unique[key] for key in sorted(unique)]
