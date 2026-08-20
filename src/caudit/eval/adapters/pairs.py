"""Pinned repository pairs, as benchmark cases.

The bridge between two halves of part 13 that were built without one.
:mod:`caudit.eval.pairs` knows how to clone, build and scan a real project, and
answers one question about it: did a confirmed finding land in a file the fix
touched? That is a *file-level* answer, and it is the right one for a pair
corpus -- a persistent false positive is a fact about a file.

Everything else in the harness speaks :class:`~caudit.eval.case.BenchmarkCase`:
per-line ground truth, the part 04 matching policy, `Metrics`, and -- the
reason this module exists -- the ablation's evidence coverage, which asks
whether the decisive *lines* were put in front of the model at all. Pairs
recorded no lines, so no ablation could run against a real repository, and the
only corpora that could were 6 synthetic mini cases and 250 synthetic CASTLE
ones. Every file in both is shorter than the flat-window control's own ±40-line
window, which makes the control read whole files and tie by construction. That
tie is the entire published retrieval result, and it says nothing.

:class:`PairsSuite` closes that. One case per pinned pair, rooted at the
**vulnerable** revision, carrying the real compilation database the recipe
produced and per-line ground truth.

Three rules shape it, and each is a way this could quietly flatter the tool:

**The lines come from the fix, not from us.** :func:`derive_truth_lines` reads
``git diff <fixed> <vulnerable>`` and takes the lines present in the vulnerable
revision and absent from the fixed one -- the lines the fix removed or changed.
Nothing about the tool's output is consulted, which is the same rule that
forbids adjudicating the maintainability set from ``clang-tidy``.

**A hand correction is data.** The derivation is mechanical and therefore
sometimes wrong: a fix commit that also refactors, renames or moves error
handling contributes lines that were never decisive, and a fix that only
*inserts* a check contributes none at all. ``RepoPair.truth_lines`` overrides
it, in the manifest, with ``note`` carrying the reasoning. A correction in the
manifest survives review; one made by patching this file does not.

**A case that cannot be built is excluded, not guessed.** No recipe is
inferred, no include path invented, no revision resolved to a tag. The suite
never fetches implicitly either: :meth:`PairsSuite.ensure_available` raises with
the exact command, the way :class:`~caudit.eval.adapters.castle.CastleSuite`
does.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import Final

from caudit.errors import CauditError
from caudit.eval.adapters.castle import cache_root
from caudit.eval.case import BenchmarkCase, GroundTruth, count_lines_of_code
from caudit.eval.pairs import PairManifest, RepoPair, load_manifest
from caudit.eval.pairs_runner import CommandRunner, build_revision, checkout_revision, run_command
from caudit.logging import get_logger
from caudit.model.cwe import family_of

__all__ = [
    "PAIRS_MANIFEST",
    "DerivedTruth",
    "PairsSuite",
    "derive_truth_lines",
    "pairs_cache_root",
]

log = get_logger(__name__)

#: The committed manifest. One place pairs are pinned, shared with `caudit pairs`.
PAIRS_MANIFEST: Final = (
    Path(__file__).resolve().parents[4] / "benchmarks" / "pairs" / "manifest.yaml"
)

#: A fix touching more of an affected file than this is not a usable ablation
#: case: the derived truth is dominated by refactoring rather than by the
#: defect, which inflates the denominator and depresses coverage for *both*
#: variants equally -- reading as "retrieval is bad" when it means "the label
#: is bad". Excluded with a reason rather than accepted, and `truth_lines`
#: overrides it, because a human who read the diff outranks a line count.
MAX_DERIVED_LINES: Final = 40

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class DerivedTruth:
    """Decisive lines for one pair, and how each one was arrived at."""

    def __init__(self, lines: Mapping[PurePosixPath, Sequence[int]], *, derived: bool) -> None:
        self.lines = {path: tuple(sorted(set(values))) for path, values in lines.items()}
        #: False when the manifest pinned them, in which case a human read the
        #: diff and the count cap does not apply.
        self.derived = derived

    @property
    def total(self) -> int:
        return sum(len(values) for values in self.lines.values())

    def exceeds_cap(self) -> bool:
        return self.derived and self.total > MAX_DERIVED_LINES


def pairs_cache_root() -> Path:
    """Where pair checkouts live.

    Under the benchmark cache beside CASTLE rather than in ``caudit-pairs/``,
    which ``make clean`` deletes: a clone plus a configure is minutes of work
    and nothing about it is generated output of a run. Relocatable with
    ``CAUDIT_BENCHMARK_CACHE``, same as every other fetched corpus.
    """
    return cache_root() / "pairs"


def derive_truth_lines(
    pair: RepoPair,
    checkout: Path,
    *,
    runner: CommandRunner = run_command,
    git: str = "git",
) -> DerivedTruth:
    """Decisive lines for ``pair``, from the fix diff or from the manifest.

    ``git diff <fixed_rev> <vulnerable_rev>`` is read in that direction on
    purpose: its added lines are the lines that exist in the vulnerable
    revision and not in the fixed one, numbered as the vulnerable revision
    numbers them. That is precisely "what the fix removed or changed", and it
    needs no hand labelling.

    A hunk that adds nothing on the vulnerable side is a fix that only
    *inserted* code -- a bounds check that was missing. There is no removed
    line to point at, so the decisive line is the first vulnerable-side line at
    the insertion point: the line the check would have guarded. Recorded as
    such, so a reader can tell the two rules apart.

    That second rule has a known limit, and it is the reason
    ``truth_lines`` exists rather than being a nicety. It assumes the insertion
    guards what follows it, which holds for a check added at the top of a body
    and fails for one appended at the *end* of a function -- where the line
    following the insertion point is the closing brace, decisive for nothing.
    The deriver cannot tell those apart and does not try; a reader can, and
    records the answer in the manifest.
    """
    if pair.truth_lines:
        return DerivedTruth(pair.truth_lines, derived=False)

    lines: dict[PurePosixPath, list[int]] = {}
    for path in pair.affected_paths:
        result = runner(
            [
                git,
                "-C",
                str(checkout),
                "diff",
                "--unified=0",
                pair.fixed_rev,
                pair.vulnerable_rev,
                "--",
                str(path),
            ],
            checkout,
            pair.build_recipe.timeout_seconds,
        )
        if not result.ok:
            log.warning("could not diff %s for %s", path, pair.pair_id)
            continue
        found = _lines_from_diff(result.output)
        if found:
            lines[path] = found
    return DerivedTruth(lines, derived=True)


def _lines_from_diff(diff: str) -> list[int]:
    """Vulnerable-side line numbers from a ``--unified=0`` diff."""
    found: list[int] = []
    cursor = 0
    for raw in diff.splitlines():
        hunk = _HUNK.match(raw)
        if hunk:
            start = int(hunk.group(1))
            count = int(hunk.group(2)) if hunk.group(2) is not None else 1
            if count == 0:
                # The fix inserted lines here and the vulnerable revision has
                # none of them. `start` is the line the insertion follows, so
                # the guarded line is the next one.
                found.append(start + 1)
                cursor = 0
            else:
                cursor = start
            continue
        if cursor and raw.startswith("+") and not raw.startswith("+++"):
            found.append(cursor)
            cursor += 1
    return sorted(set(found))


class PairsSuite:
    """Pinned repository pairs, at their vulnerable revisions, as cases.

    Cases are built lazily and cached: checking out and configuring a real
    project costs minutes, and a grid asks for the same case once per
    configuration.
    """

    name = "pairs"

    def __init__(
        self,
        manifest_path: Path | None = None,
        workspace: Path | None = None,
        *,
        runner: CommandRunner = run_command,
        git: str = "git",
    ) -> None:
        self._manifest_path = manifest_path or PAIRS_MANIFEST
        self._workspace = (workspace or pairs_cache_root()).resolve()
        self._runner = runner
        self._git = git
        self._cases: dict[str, BenchmarkCase] = {}
        self._databases: dict[str, Path] = {}
        #: Pairs that could not become cases, and why. Read by the caller.
        self.excluded: dict[str, str] = {}

    # ------------------------------------------------------------ availability

    @cached_property
    def manifest(self) -> PairManifest:
        if not self._manifest_path.is_file():
            return PairManifest(version="0")
        return load_manifest(self._manifest_path)

    def is_available(self) -> bool:
        return bool(self.manifest.pairs)

    def ensure_available(self) -> None:
        if self.is_available():
            return
        raise CauditError(
            f"no repository pairs are pinned in {self._manifest_path}",
            hint=(
                "Pin one first: benchmarks/pairs/README.md has the five-step procedure. "
                "A pair needs a full vulnerable SHA, a full fixed SHA, the files the fix "
                "touched, and a build recipe that produces a compilation database. "
                "Nothing here invents any of them."
            ),
        )

    # -------------------------------------------------------------- case loading

    def case_ids(self) -> Sequence[str]:
        return tuple(sorted(pair.pair_id for pair in self.manifest.pairs))

    def _pair(self, case_id: str) -> RepoPair:
        for pair in self.manifest.pairs:
            if pair.pair_id == case_id:
                return pair
        raise FileNotFoundError(f"no such pinned pair: {case_id}")

    def checkout_for(self, pair: RepoPair) -> Path:
        return self._workspace / pair.pair_id / pair.vulnerable_rev[:12]

    def load(self, case_id: str) -> BenchmarkCase:
        """One case, at the vulnerable revision, built and labelled.

        Raises for a pair that cannot be checked out or built, rather than
        returning a case with no database: an empty case would be scored, and a
        pair that failed to build must be excluded from both halves of every
        fraction. :meth:`cases` turns the raise into a recorded exclusion.
        """
        self.ensure_available()
        if case_id in self._cases:
            return self._cases[case_id]

        pair = self._pair(case_id)
        checkout = self.checkout_for(pair)
        if not checkout_revision(
            pair, pair.vulnerable_rev, checkout, runner=self._runner, git=self._git
        ):
            raise CauditError(
                f"could not check out {pair.repo_url} at {pair.vulnerable_rev}",
                hint="The pair is pinned by full SHA; a revision that no longer exists "
                "upstream is a manifest problem, not a tool problem.",
            )

        database = build_revision(pair, checkout, runner=self._runner)
        if database is None:
            raise CauditError(
                f"the build recipe for {pair.pair_id} produced no "
                f"{pair.build_recipe.compile_commands}",
                hint=(
                    f"Requires: {', '.join(pair.build_recipe.requires) or 'nothing recorded'}. "
                    "A pair that cannot be built is excluded with a reason and scored in "
                    "neither the numerator nor the denominator."
                ),
            )

        truth = derive_truth_lines(pair, checkout, runner=self._runner, git=self._git)
        if truth.exceeds_cap():
            raise CauditError(
                f"the fix for {pair.pair_id} changed {truth.total} lines across its affected "
                f"paths, over the {MAX_DERIVED_LINES}-line cap for a derived label",
                hint=(
                    "A fix that also refactors contributes lines that were never decisive, "
                    "and they depress coverage for every retrieval variant equally -- which "
                    "reads as a result about retrieval and is a fact about the label. Pin "
                    "the decisive lines explicitly under truth_lines, with the reasoning in "
                    "note, or choose a more focused fix commit."
                ),
            )
        if truth.total == 0:
            raise CauditError(
                f"no decisive lines could be derived for {pair.pair_id}",
                hint=(
                    "The diff between the two revisions is empty for every affected path. "
                    "Check that affected_paths names files the fix actually changed."
                ),
            )

        family = family_of(pair.cwe)
        if family is None:
            raise CauditError(
                f"pair {pair.pair_id} names {pair.cwe}, which is outside the allowlist",
                hint="A pair whose CWE has no weakness family cannot be scored by family.",
            )

        origin = "manifest (hand-confirmed)" if not truth.derived else "fix diff"
        ground_truth = [
            GroundTruth(
                path=path,
                line=line,
                cwe=pair.cwe,
                family=family,
                variant="vulnerable",
                note=f"{pair.cve or pair.pair_id}: decisive line from {origin}",
            )
            for path, lines in sorted(truth.lines.items())
            for line in lines
        ]

        case = BenchmarkCase(
            case_id=case_id,
            root=checkout,
            compile_commands=database,
            ground_truth=ground_truth,
            lines_of_code=count_lines_of_code(
                [checkout / Path(*path.parts) for path in pair.affected_paths]
            ),
            family=family,
            description=(
                f"{pair.cve or 'no CVE'} in {pair.repo_url} at {pair.vulnerable_rev[:12]}; "
                f"fixed in {pair.fixed_rev[:12]}"
            ),
        )
        self._cases[case_id] = case
        self._databases[case_id] = database
        return case

    def cases(self) -> Sequence[BenchmarkCase]:
        """Every pair that could be made into a case, with the rest recorded.

        A pair that fails here is excluded with its reason in
        :attr:`excluded` rather than raising, because one unbuildable pair must
        not stop a corpus -- the same rule the pair harness applies, and the
        reason a benchmark never quietly loses its hard cases.
        """
        loaded: list[BenchmarkCase] = []
        for case_id in self.case_ids():
            try:
                loaded.append(self.load(case_id))
            except CauditError as exc:
                self.excluded[case_id] = str(exc)
                log.warning("pair %s excluded: %s", case_id, exc)
        return tuple(loaded)

    # ------------------------------------------------------------- build glue

    def materialize_compile_commands(self, case_id: str, dest_dir: Path) -> Path:
        """The database the recipe produced, in place.

        Unlike the mini and CASTLE suites there is nothing to write: a real
        build already emitted a real compilation database with absolute paths
        that are correct for this machine, and copying it elsewhere would only
        create a second copy to get out of date. ``dest_dir`` is accepted to
        satisfy the hook's shape and deliberately unused.
        """
        del dest_dir
        if case_id not in self._databases:
            self.load(case_id)
        return self._databases[case_id]
