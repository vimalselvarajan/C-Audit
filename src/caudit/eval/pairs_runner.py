"""Scanning a real repository pair: checkout, build, scan, decide.

:mod:`caudit.eval.pairs` owns the accounting — what counts as a detection,
what is excluded, what may never be pooled. This is the half that goes and
gets the code: it clones the repository once, checks out each pinned revision,
runs the recorded build recipe, and scans whatever compilation database the
recipe produced.

Three decisions worth stating, because each one is a way this could quietly
flatter the tool:

**A detection must be in a file the fix touched.** A scan of a real repository
reports findings all over it. Counting any of them as "this pair was detected"
would score the corpus on unrelated true positives, and every pair would look
found. ``RepoPair.affected_paths`` is the filter, and it is required on the
manifest for exactly this reason.

**Only confirmed findings count.** A review-required item is the tool saying it
could not stand the claim up. Crediting it as a detection would merge the two
counts the spec keeps apart, in the one place where the merge would be
invisible.

**A failure is a failure, never a miss.** A checkout that does not resolve, a
recipe whose command exits non-zero, a database that never appears — each
excludes the pair with the reason, and the pair enters neither the numerator
nor the denominator.

Nothing here reaches the network or a compiler on its own: the command runner
is injectable, which is what lets the rules above be tested offline while the
real thing waits for a machine that has git, a toolchain, and pinned pairs.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter

from rich.console import Console

from caudit.application.pipeline import CandidateOutcome
from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.eval.pairs import RepoPair, RevisionResult
from caudit.logging import get_logger

__all__ = [
    "CommandResult",
    "CommandRunner",
    "RepositoryScanner",
    "build_revision",
    "checkout_revision",
    "detected_in",
    "detections_for",
    "run_command",
]

log = get_logger(__name__)


@dataclass(frozen=True)
class CommandResult:
    """What one shell step did. ``ok`` is the only thing callers branch on."""

    ok: bool
    output: str = ""

    @classmethod
    def failure(cls, output: str) -> CommandResult:
        return cls(ok=False, output=output)


#: Runs one command in one directory. Injectable so the checkout-and-build
#: logic is testable without git, a network, or a C toolchain.
CommandRunner = Callable[[Sequence[str], Path, float], CommandResult]


def run_command(command: Sequence[str], cwd: Path, timeout: float) -> CommandResult:
    """The real runner: a subprocess, captured, with a timeout.

    ``shell=False``. A recipe step is a list of arguments, so a repository URL
    or a revision from a manifest cannot become part of a shell command line.
    """
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandResult.failure(f"{' '.join(command)}: {exc}")
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-5:]
        return CommandResult.failure(
            f"{' '.join(command)} exited {completed.returncode}: {' / '.join(tail)}"
        )
    return CommandResult(ok=True, output=completed.stdout)


def checkout_revision(
    pair: RepoPair,
    revision: str,
    checkout: Path,
    *,
    runner: CommandRunner = run_command,
    git: str = "git",
) -> bool:
    """Put ``revision`` of ``pair`` in ``checkout``. ``True`` when it is there.

    Module-level rather than a method because two callers need it: the pair
    scanner, which scans both revisions, and
    :class:`~caudit.eval.adapters.pairs.PairsSuite`, which needs only the
    vulnerable one as a benchmark case root. A second implementation would
    eventually clone differently from the one the pair corpus uses, and the two
    corpora would stop being the same checkout.
    """
    if (checkout / ".git").is_dir():
        return runner(
            [git, "-C", str(checkout), "checkout", "--quiet", revision],
            checkout,
            pair.build_recipe.timeout_seconds,
        ).ok

    checkout.parent.mkdir(parents=True, exist_ok=True)
    if checkout.exists():
        shutil.rmtree(checkout)
    cloned = runner(
        [git, "clone", "--quiet", pair.repo_url, str(checkout)],
        checkout.parent,
        pair.build_recipe.timeout_seconds,
    )
    if not cloned.ok:
        log.warning("clone failed for %s: %s", pair.pair_id, cloned.output)
        return False
    return runner(
        [git, "-C", str(checkout), "checkout", "--quiet", revision],
        checkout,
        pair.build_recipe.timeout_seconds,
    ).ok


def build_revision(
    pair: RepoPair, checkout: Path, *, runner: CommandRunner = run_command
) -> Path | None:
    """Run the recorded recipe in ``checkout``. ``None`` when no database results."""
    recipe = pair.build_recipe
    for step in recipe.steps:
        result = runner(step.split(), checkout, recipe.timeout_seconds)
        if not result.ok:
            log.warning("build step failed for %s: %s", pair.pair_id, result.output)
            return None
    database = checkout / recipe.compile_commands
    return database if database.is_file() else None


def detections_for(outcomes: Sequence[CandidateOutcome], pair: RepoPair) -> list[CandidateOutcome]:
    """The confirmed findings this pair is about, and only those.

    Both filters matter. A confirmed finding elsewhere in a large repository
    says nothing about this pair, and an unconfirmed one in the right file is
    the tool saying it could not stand the claim up — crediting it would merge
    the two counts the spec keeps apart, in the one place the merge would be
    invisible.
    """
    return [
        outcome
        for outcome in outcomes
        if outcome.finding.is_confirmed and pair.touches(outcome.finding.location.path)
    ]


def detected_in(outcomes: Sequence[CandidateOutcome], pair: RepoPair) -> bool:
    """Whether this pair's defect was reported at this revision."""
    return bool(detections_for(outcomes, pair))


def _citations_resolved(outcomes: Sequence[CandidateOutcome], pair: RepoPair) -> bool:
    """Whether every claim behind this pair's detections resolved.

    Read from the gate that already checked them rather than re-derived here:
    a second, weaker resolution check would eventually disagree with the one
    the report was built from, and the pair corpus would be grading a different
    tool. An outcome with no gate is an analyzer-only run, where the only
    citation is the analyzer's own region and part 08 resolved it.
    """
    return all(
        outcome.gate is None or outcome.gate.resolution_rate >= 1.0
        for outcome in detections_for(outcomes, pair)
    )


@dataclass
class RepositoryScanner:
    """A :data:`~caudit.eval.pairs.ScanRevision` that really scans.

    One clone per repository, reused across both revisions of a pair — cloning
    twice would double the slowest step of the slowest corpus for nothing.
    """

    config: Config
    workspace: Path
    console: Console
    #: Injected so the whole checkout-and-build path is testable offline.
    runner: CommandRunner = run_command
    git: str = "git"
    #: Revisions already scanned, so a re-run of one pair set does not rebuild.
    _built: dict[tuple[str, str], Path | None] = field(default_factory=dict)

    def __call__(self, pair: RepoPair, revision: str) -> RevisionResult:
        began = perf_counter()
        try:
            database = self._prepare(pair, revision)
        except CauditError as exc:
            return RevisionResult(detected=False, failure=str(exc))
        if database is None:
            return RevisionResult(
                detected=False,
                failure=(
                    f"the build recipe produced no {pair.build_recipe.compile_commands}. "
                    f"Requires: {', '.join(pair.build_recipe.requires) or 'nothing recorded'}"
                ),
            )

        from caudit.application.scan import run_scan

        checkout = self._checkout_dir(pair, revision)
        try:
            result = run_scan(
                checkout,
                database,
                self.config,
                out=self.workspace / "reports" / pair.pair_id / revision[:12],
                console=self.console,
            )
        except CauditError as exc:
            return RevisionResult(detected=False, failure=f"the scan did not complete: {exc}")

        outcomes = result.pipeline.outcomes
        tokens = result.pipeline.account.total_tokens if result.pipeline.account else 0
        return RevisionResult(
            detected=detected_in(outcomes, pair),
            citation_valid=_citations_resolved(outcomes, pair),
            tokens=tokens,
            wall_time_s=perf_counter() - began,
        )

    # ------------------------------------------------------------- internals

    def _checkout_dir(self, pair: RepoPair, revision: str) -> Path:
        return self.workspace / "checkouts" / pair.pair_id / revision[:12]

    def _prepare(self, pair: RepoPair, revision: str) -> Path | None:
        """Check out one revision and build it. ``None`` if no database appeared."""
        key = (pair.pair_id, revision)
        if key in self._built:
            return self._built[key]

        checkout = self._checkout_dir(pair, revision)
        if not self._clone(pair, revision, checkout):
            raise CauditError(
                f"could not check out {pair.repo_url} at {revision}",
                hint="The pair is pinned by full SHA; a revision that no longer exists "
                "upstream is a manifest problem, not a tool problem.",
            )
        database = self._build(pair, checkout)
        self._built[key] = database
        return database

    def _clone(self, pair: RepoPair, revision: str, checkout: Path) -> bool:
        return checkout_revision(pair, revision, checkout, runner=self.runner, git=self.git)

    def _build(self, pair: RepoPair, checkout: Path) -> Path | None:
        return build_revision(pair, checkout, runner=self.runner)
