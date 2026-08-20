"""Vulnerable and fixed revisions of the same repository.

The strongest signal available without hand-labelling: scan one project twice,
at the revision that had the defect and at the revision that fixed it. A
detection that appears in the first and is gone from the second is real. One
that survives the fix is a false positive **with a known answer** — which is
rarer and more valuable than an unlabelled false positive, because nobody has
to adjudicate it.

Three rules shape this module, and none of them is a convenience:

**A pair that will not build is excluded and recorded.** Quietly dropping a
repository whose build recipe stopped working is how a benchmark becomes
flattering: the hard projects fall out and the remaining score goes up. An
excluded pair is named, with the reason, and is counted in neither the numerator
nor the denominator.

**A detection at the fixed revision is a false positive, not a null result.**
It is the one place a benchmark can be certain the tool is wrong, so it is
scored rather than ignored.

**Held-out pairs are used once per finalized policy version.** Every access is
recorded, and a second access for the same version warns. A held-out set
consulted repeatedly is a development set with a more reassuring name.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.logging import get_logger
from caudit.model.cwe import CweId, WeaknessFamily, family_of

__all__ = [
    "BuildRecipe",
    "ExcludedPair",
    "HeldOutLedger",
    "PairManifest",
    "PairOutcome",
    "PairResults",
    "PairSet",
    "RepoPair",
    "load_manifest",
    "score_pairs",
]

log = get_logger(__name__)


class PairSet(StrEnum):
    """Which half of the corpus a pair belongs to.

    Disjoint by construction and by test. A pair in both sets would let a
    policy be tuned on data it is then measured against, which is the failure
    the split exists to prevent.
    """

    DEVELOPMENT = "development"
    HELD_OUT = "held_out"


class BuildRecipe(BaseModel):
    """How to produce a compilation database for one revision.

    Recorded rather than inferred, for the same reason C Audit never guesses
    include paths: a database produced by a command nobody wrote down is not
    reproducible, and a pair scored against one is not evidence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Shell commands, in order, run from the checkout root. The last one must
    #: leave a compilation database at :attr:`compile_commands`.
    steps: list[str] = Field(min_length=1)
    #: Where the database lands, relative to the checkout root.
    compile_commands: PurePosixPath = PurePosixPath("build/compile_commands.json")
    #: Packages the recipe needs. Named so a failure can say what was missing
    #: rather than only that a command exited non-zero.
    requires: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=1800.0, gt=0.0)


class RepoPair(BaseModel):
    """One CVE-linked vulnerable/fixed revision pair, pinned by SHA."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pair_id: str = Field(min_length=1)
    repo_url: str = Field(min_length=1)
    #: Full SHAs. A tag or a branch would let the pair change underneath a
    #: recorded result, which is the same failure as an unpinned dependency.
    vulnerable_rev: str = Field(min_length=7)
    fixed_rev: str = Field(min_length=7)
    cve: str | None = None
    cwe: CweId
    build_recipe: BuildRecipe
    #: Files the fix touched. A detection outside them at the vulnerable
    #: revision is not evidence that this pair was detected.
    affected_paths: list[PurePosixPath] = Field(min_length=1)
    #: Decisive lines per affected path, in the *vulnerable* revision's
    #: numbering, confirmed by a human against the fix diff.
    #:
    #: Empty means "derive them from the diff", which is what
    #: :func:`~caudit.eval.adapters.pairs.derive_truth_lines` does. Present
    #: means the derivation was read and corrected, and the correction is
    #: recorded *here* rather than patched into the deriver -- a hand
    #: confirmation that lives in the manifest survives review, and one that
    #: lives in code is invisible to anyone reading the corpus. ``note``
    #: carries the reasoning for whatever was dropped.
    #:
    #: Only the pair *suite* reads this; the pair harness itself still matches
    #: at file level, because a persistent false positive is a fact about a
    #: file and not about a line.
    truth_lines: dict[PurePosixPath, list[int]] = Field(default_factory=dict)
    pair_set: PairSet = PairSet.DEVELOPMENT
    note: str = ""

    @model_validator(mode="after")
    def _check_truth_lines_are_affected(self) -> Self:
        stray = sorted(str(path) for path in self.truth_lines if not self.touches(path))
        if stray:
            raise ValueError(
                f"pair {self.pair_id} pins truth lines in {', '.join(stray)}, which the fix "
                "did not touch. A decisive line outside affected_paths is either a mistake "
                "or a missing affected_paths entry; both are manifest errors"
            )
        bad = sorted(
            f"{path}:{line}"
            for path, lines in self.truth_lines.items()
            for line in lines
            if line < 1
        )
        if bad:
            raise ValueError(f"pair {self.pair_id} pins non-positive truth lines: {', '.join(bad)}")
        return self

    @model_validator(mode="after")
    def _check_revisions_differ(self) -> Self:
        if self.vulnerable_rev == self.fixed_rev:
            raise ValueError(
                f"pair {self.pair_id} names one revision twice ({self.vulnerable_rev}); "
                "a pair whose two sides are identical cannot distinguish a real "
                "detection from a persistent false positive"
            )
        return self

    @property
    def family(self) -> WeaknessFamily | None:
        return family_of(self.cwe)

    def touches(self, path: PurePosixPath | str) -> bool:
        """Whether ``path`` is one the fix changed."""
        candidate = PurePosixPath(path)
        return any(candidate == affected for affected in self.affected_paths)


class PairOutcome(BaseModel):
    """What scanning both revisions of one pair produced."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pair_id: str = Field(min_length=1)
    detected_in_vulnerable: bool
    #: A detection here is a false positive with a known answer.
    detected_in_fixed: bool
    #: Whether every citation in the detections resolved. A detection whose
    #: evidence does not resolve is not a detection this corpus credits.
    citation_valid: bool = True
    tokens: int = Field(default=0, ge=0)
    wall_time_s: float = Field(default=0.0, ge=0.0)
    #: The policy versions this outcome was produced under. Results are never
    #: pooled across versions, so an outcome that cannot name them is unusable.
    policy_versions: dict[str, str] = Field(default_factory=dict)

    @property
    def true_positive(self) -> bool:
        """Found where the defect was, with evidence that resolved."""
        return self.detected_in_vulnerable and self.citation_valid

    @property
    def false_positive(self) -> bool:
        """Still reported after the fix. The one certainty a pair set buys."""
        return self.detected_in_fixed

    @property
    def missed(self) -> bool:
        return not self.detected_in_vulnerable


class ExcludedPair(BaseModel):
    """A pair that could not be run, and why. Never silently dropped."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pair_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    #: Which revision failed, when only one did.
    revision: str | None = None

    def describe(self) -> str:
        where = f" at {self.revision}" if self.revision else ""
        return f"{self.pair_id}{where}: {self.reason}"


class PairManifest(BaseModel):
    """Every pinned pair, split into development and held-out sets."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    pairs: list[RepoPair] = Field(default_factory=list)
    #: Pairs known to be unusable, with the reason, so a shrinking corpus is
    #: visible in the manifest rather than only in a run's output.
    excluded: list[ExcludedPair] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_ids_are_unique_and_sets_disjoint(self) -> Self:
        seen: dict[str, PairSet] = {}
        duplicated: list[str] = []
        overlapping: list[str] = []
        for pair in self.pairs:
            if pair.pair_id in seen:
                (overlapping if seen[pair.pair_id] is not pair.pair_set else duplicated).append(
                    pair.pair_id
                )
                continue
            seen[pair.pair_id] = pair.pair_set
        if overlapping:
            raise ValueError(
                f"pair id(s) {', '.join(sorted(set(overlapping)))} appear in both the "
                "development and held-out sets; a policy tuned on a pair cannot then be "
                "measured against it"
            )
        if duplicated:
            raise ValueError(f"duplicate pair id(s): {', '.join(sorted(set(duplicated)))}")
        return self

    def of(self, pair_set: PairSet) -> list[RepoPair]:
        """One set's pairs, in manifest order."""
        return [pair for pair in self.pairs if pair.pair_set is pair_set]

    @property
    def development(self) -> list[RepoPair]:
        return self.of(PairSet.DEVELOPMENT)

    @property
    def held_out(self) -> list[RepoPair]:
        return self.of(PairSet.HELD_OUT)

    def pair_ids(self, pair_set: PairSet | None = None) -> set[str]:
        chosen = self.pairs if pair_set is None else self.of(pair_set)
        return {pair.pair_id for pair in chosen}


def load_manifest(path: Path) -> PairManifest:
    """Read ``benchmarks/pairs/manifest.yaml``.

    YAML rather than JSON because a build recipe is a list of shell commands a
    human maintains, and a recipe nobody can read is a recipe nobody fixes.
    """
    import yaml

    if not path.is_file():
        raise FileNotFoundError(
            f"no pair manifest at {path}. The corpus is fetched, not committed; see "
            "benchmarks/pairs/README.md for what has to be supplied."
        )
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return PairManifest.model_validate(raw)


# ----------------------------------------------------------------- held-out


@dataclass
class HeldOutLedger:
    """Records every access to the held-out set, and warns on a repeat.

    The spec's rule is that held-out data is used **once per finalized policy
    version**. Enforcing that by refusing would be worse than recording it: a
    legitimate re-run after a crash would be blocked, and the fix would be to
    delete the ledger. So it warns, records, and lets the record be published —
    a set consulted five times under one policy version is visible to anyone
    reading the results.
    """

    path: Path
    #: Injected so a test can assert on what was recorded without a clock.
    now: Callable[[], datetime] = lambda: datetime.now(UTC)

    def entries(self) -> list[dict[str, str]]:
        if not self.path.is_file():
            return []
        loaded = json.loads(self.path.read_text(encoding="utf-8"))
        return [entry for entry in loaded if isinstance(entry, dict)]

    def accesses_for(self, policy_version: str) -> int:
        return sum(1 for entry in self.entries() if entry.get("policy_version") == policy_version)

    def record(self, policy_version: str, *, reason: str = "") -> int:
        """Record one access. Returns how many there have now been."""
        previous = self.accesses_for(policy_version)
        if previous:
            log.warning(
                "the held-out pair set has already been used %d time(s) under policy "
                "version %s. Repeated use turns a held-out set into a development set; "
                "the count is recorded in %s and belongs in any published result.",
                previous,
                policy_version,
                self.path,
            )
        entries = self.entries()
        entries.append(
            {
                "policy_version": policy_version,
                "at": self.now().isoformat(),
                "reason": reason or "unstated",
            }
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return previous + 1

    def caveat(self, policy_version: str) -> str | None:
        """A sentence for the results document, or ``None`` if used once."""
        count = self.accesses_for(policy_version)
        if count <= 1:
            return None
        return (
            f"the held-out set was used {count} times under policy version "
            f"{policy_version}; results from it are no longer held-out results"
        )


# ------------------------------------------------------------------ running


#: What one revision's scan reports back: whether the defect was found in the
#: affected paths, whether every citation resolved, and what it cost. Injected
#: as a callable so the harness can be tested without a network, a clone, or a
#: build — the thing under test here is the accounting, not the scanner.
ScanRevision = Callable[[RepoPair, str], "RevisionResult"]


@dataclass(frozen=True)
class RevisionResult:
    """One revision's scan, reduced to what a pair outcome needs."""

    detected: bool
    citation_valid: bool = True
    tokens: int = 0
    wall_time_s: float = 0.0
    #: Set when the revision could not be scanned at all — a checkout that
    #: failed, a build recipe that did not produce a database. A pair with one
    #: of these is excluded rather than counted as a miss.
    failure: str | None = None

    @property
    def usable(self) -> bool:
        return self.failure is None


@dataclass
class PairResults:
    """Outcomes and exclusions from one run over a pair set."""

    outcomes: list[PairOutcome] = field(default_factory=list)
    excluded: list[ExcludedPair] = field(default_factory=list)

    @property
    def true_positives(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.true_positive)

    @property
    def false_positives(self) -> int:
        """Detections that survived the fix. Counted, never ignored."""
        return sum(1 for outcome in self.outcomes if outcome.false_positive)

    @property
    def missed(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.missed)

    @property
    def scored(self) -> int:
        """Pairs that actually ran. Excluded pairs are in neither ratio."""
        return len(self.outcomes)

    def describe(self) -> str:
        excluded = f", {len(self.excluded)} excluded" if self.excluded else ""
        return (
            f"{self.scored} pair(s) scored: {self.true_positives} detected, "
            f"{self.missed} missed, {self.false_positives} still reported after the "
            f"fix{excluded}"
        )


def run_pairs(
    pairs: Iterable[RepoPair],
    scan: ScanRevision,
    *,
    policy_versions: Mapping[str, str],
) -> PairResults:
    """Scan both revisions of every pair, recording exclusions rather than hiding them.

    A revision that could not be checked out or built excludes the whole pair:
    with only one side, a detection cannot be told from a false positive, and
    counting it either way would be inventing the answer.
    """
    results = PairResults()
    for pair in pairs:
        vulnerable = scan(pair, pair.vulnerable_rev)
        if not vulnerable.usable:
            results.excluded.append(
                ExcludedPair(
                    pair_id=pair.pair_id,
                    reason=vulnerable.failure or "the vulnerable revision could not be scanned",
                    revision=pair.vulnerable_rev,
                )
            )
            continue
        fixed = scan(pair, pair.fixed_rev)
        if not fixed.usable:
            results.excluded.append(
                ExcludedPair(
                    pair_id=pair.pair_id,
                    reason=(
                        f"{fixed.failure or 'the fixed revision could not be scanned'}. "
                        "The vulnerable revision scanned, but one side alone cannot tell a "
                        "detection from a false positive"
                    ),
                    revision=pair.fixed_rev,
                )
            )
            continue
        results.outcomes.append(
            PairOutcome(
                pair_id=pair.pair_id,
                detected_in_vulnerable=vulnerable.detected,
                detected_in_fixed=fixed.detected,
                citation_valid=vulnerable.citation_valid and fixed.citation_valid,
                tokens=vulnerable.tokens + fixed.tokens,
                wall_time_s=vulnerable.wall_time_s + fixed.wall_time_s,
                policy_versions=dict(sorted(policy_versions.items())),
            )
        )
    return results


class PairScore(BaseModel):
    """Detection quality over a pair set. Three numbers, never one.

    There is deliberately no F-score here. A pair set answers two different
    questions — did we find the defect, and did we stop reporting it once it
    was fixed — and a harmonic mean of the two hides which of them moved.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    pair_set: PairSet
    scored: int = Field(ge=0)
    detected: int = Field(ge=0)
    #: Detections that persisted after the fix.
    persisted: int = Field(ge=0)
    excluded: int = Field(ge=0)
    total_tokens: int = Field(default=0, ge=0)
    total_wall_time_s: float = Field(default=0.0, ge=0.0)
    policy_versions: dict[str, str] = Field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        """Detected over scored. 1.0 when nothing was scored — vacuously."""
        return 1.0 if not self.scored else self.detected / self.scored

    @property
    def persistence_rate(self) -> float:
        """The share of detections still reported after the fix. Lower is better."""
        return 0.0 if not self.detected else self.persisted / self.detected

    def describe(self) -> str:
        return (
            f"{self.pair_set}: {self.detected}/{self.scored} detected "
            f"({self.detection_rate:.2f}), {self.persisted} persisted after the fix "
            f"({self.persistence_rate:.2f}), {self.excluded} excluded"
        )


def score_pairs(
    results: PairResults, pair_set: PairSet, *, policy_versions: Mapping[str, str]
) -> PairScore:
    """Reduce one run to the three numbers the milestone asks for.

    Excluded pairs are reported and are in neither ratio. They are not misses:
    the tool was never given the chance to look.
    """
    _assert_one_policy(results.outcomes)
    return PairScore(
        pair_set=pair_set,
        scored=results.scored,
        detected=results.true_positives,
        persisted=results.false_positives,
        excluded=len(results.excluded),
        total_tokens=sum(outcome.tokens for outcome in results.outcomes),
        total_wall_time_s=sum(outcome.wall_time_s for outcome in results.outcomes),
        policy_versions=dict(sorted(policy_versions.items())),
    )


def _assert_one_policy(outcomes: Sequence[PairOutcome]) -> None:
    """Refuse to reduce outcomes produced under different policies.

    Pooling across versions is the mistake that makes a results table look
    like a trend when it is a mixture, so it raises rather than warns.
    """
    seen = {
        json.dumps(outcome.policy_versions, sort_keys=True)
        for outcome in outcomes
        if outcome.policy_versions
    }
    if len(seen) > 1:
        raise ValueError(
            "these outcomes were produced under "
            f"{len(seen)} different policy configurations and cannot be pooled: "
            + "; ".join(sorted(seen))
        )


def iter_paths(pair: RepoPair) -> Iterator[PurePosixPath]:
    """The files the fix touched, which is where a detection has to land."""
    yield from pair.affected_paths
