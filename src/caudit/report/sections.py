"""What goes in the report, and which half of it each finding belongs to.

The evidence gate runs *here*, before anything is rendered. Every citation a
finding makes is resolved against the scanned revision first; a finding whose
location, evidence region, or symbol claim does not hold is moved to **needs
review** carrying the resolver's own reason. A confirmed finding with an
unverified citation is therefore not something this module chooses not to
emit — it is something it cannot construct.

Confirmed and needs-review are two lists with two counts. There is
deliberately no property, field, or helper anywhere in this package that adds
them, and a test asserts the absence rather than trusting the convention.

The gate here is deliberately the *cheap* one — it resolves what a finding
already claims. Part 11 is the authoritative gate, and it runs before this one
in the assembled pipeline: it decides whether a model's proposal becomes a
finding at all. Both route on the same
:data:`~caudit.evidence.resolver.REASON_FOR_STATUS` table, which is why that
table lives with :class:`~caudit.evidence.resolver.ResolutionStatus` rather
than in either consumer.

Two extensions to the interface in ``my_docs/plan/08-deterministic-reporting.md``:

* :attr:`ReportSections.unresolved` keeps the resolver's exact verdict per
  finding id. :class:`~caudit.model.finding.ReviewReason` is deliberately
  coarser than :class:`~caudit.evidence.resolver.ResolutionStatus` — part 11
  branches on the coarse value — so without this the precise reason AC-08-12
  asks for would be lost between the gate and the page.
* :attr:`ReportSections.notes` carries run-level statements that are not
  blind spots, such as "no analyzer ran". A :class:`Limitation` says what was
  not looked at; these say what the reader should know about the run itself.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import PurePosixPath
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.evidence.resolver import (
    REASON_FOR_STATUS,
    Citation,
    CitationResolver,
    Resolution,
)
from caudit.finding_policy.ranking import rank_findings
from caudit.intake.plan import Coverage, ExclusionReason
from caudit.model.finding import (
    Confidence,
    Finding,
    Limitation,
    ReviewReason,
)

__all__ = [
    "ReportSections",
    "build_sections",
    "citations_of",
    "sort_findings",
]


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """One section's findings in report order — part 12's ranking.

    Kept as a name because part 08's callers spell it, but there is deliberately
    only one ordering in this codebase and it lives in
    :mod:`caudit.finding_policy.ranking`. A second sort here would be a second answer to
    "why is this at the top", and only one of them would be the one the report
    explains.

    Applied to each section separately, after :func:`build_sections` has split
    them, which is what makes "a review item never appears in the confirmed
    ranking" a property of the call graph rather than of the comparison
    function.
    """
    return rank_findings(findings)


def citations_of(finding: Finding) -> list[Citation]:
    """Every claim the finding makes about the tree, in rendering order.

    The location is cited as a region only. Its symbol is verified through the
    evidence item whose region spans the function, because "this line is in
    ``f``" is a claim about a span, and checking the name against the single
    cited line would pass for any line that happens to mention it.
    """
    citations = [Citation.from_region(finding.location, label="location")]
    for item in finding.evidence:
        citations.append(
            Citation.from_region(
                item.region,
                symbol=item.symbol.name if item.symbol else None,
                label=str(item.kind),
            )
        )
    return citations


class ReportSections(BaseModel):
    """The rendered shape of one run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    confirmed: list[Finding] = Field(default_factory=list)
    needs_review: list[Finding] = Field(default_factory=list)
    coverage: Coverage
    limitations: list[Limitation] = Field(default_factory=list)
    excluded: list[tuple[PurePosixPath, ExclusionReason]] = Field(default_factory=list)
    #: ``finding_id`` → ``"<resolution status>: <detail>"`` for every finding
    #: the evidence gate moved. Empty for a run in which everything resolved.
    unresolved: dict[str, str] = Field(default_factory=dict)
    #: Run-level statements that are not blind spots. Rendered verbatim.
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_separation(self) -> Self:
        """The two sections are disjoint, and each holds only its own kind."""
        confirmed_ids = {finding.finding_id for finding in self.confirmed}
        review_ids = {finding.finding_id for finding in self.needs_review}
        both = confirmed_ids & review_ids
        if both:
            raise ValueError(f"finding(s) in both sections: {sorted(both)}")
        misplaced = [f.finding_id for f in self.confirmed if not f.is_confirmed]
        if misplaced:
            raise ValueError(f"review-required finding(s) in the confirmed section: {misplaced}")
        promoted = [f.finding_id for f in self.needs_review if f.is_confirmed]
        if promoted:
            raise ValueError(f"confirmed finding(s) in the needs-review section: {promoted}")
        return self

    @property
    def confirmed_count(self) -> int:
        return len(self.confirmed)

    @property
    def review_count(self) -> int:
        """Counted apart from :attr:`confirmed_count`, and never added to it."""
        return len(self.needs_review)

    @property
    def is_empty(self) -> bool:
        return not self.confirmed and not self.needs_review

    def region_hashes(self) -> dict[str, str]:
        """``finding_id`` → the hash of its cited location, sorted by key."""
        pairs = {
            finding.finding_id: finding.location.sha256
            for finding in [*self.confirmed, *self.needs_review]
        }
        return {key: pairs[key] for key in sorted(pairs)}


def build_sections(
    findings: Iterable[Finding],
    *,
    resolver: CitationResolver,
    coverage: Coverage,
    limitations: Sequence[Limitation] = (),
    excluded: Sequence[tuple[PurePosixPath, ExclusionReason]] = (),
    notes: Sequence[str] = (),
) -> ReportSections:
    """Run the evidence gate over every finding and split the two sections.

    A finding reaches ``confirmed`` only by resolving every citation it makes
    *and* arriving already confirmed. Everything else lands in needs-review
    with a reason, which is the difference between a report that omits a
    doubtful finding and one that shows it labelled.
    """
    confirmed: list[Finding] = []
    review: list[Finding] = []
    unresolved: dict[str, str] = {}

    for finding in findings:
        failure = _first_failure(resolver.resolve_all(citations_of(finding)))
        if failure is not None:
            unresolved[finding.finding_id] = f"{failure.status}: {failure.detail}"
            review.append(_downgrade(finding, failure))
        elif finding.is_confirmed:
            confirmed.append(finding)
        else:
            review.append(finding)

    return ReportSections(
        confirmed=sort_findings(confirmed),
        needs_review=sort_findings(review),
        coverage=coverage,
        limitations=list(limitations),
        excluded=sorted(excluded, key=lambda item: (str(item[0]), str(item[1]))),
        unresolved={key: unresolved[key] for key in sorted(unresolved)},
        notes=list(notes),
    )


def _first_failure(resolutions: Sequence[Resolution]) -> Resolution | None:
    """The first citation that did not hold, in the order the report cites them."""
    for resolution in resolutions:
        if not resolution.ok:
            return resolution
    return None


def _downgrade(finding: Finding, failure: Resolution) -> Finding:
    """Move a finding to review-required, keeping everything else intact.

    Nothing is edited away: the impact, the evidence, and the provenance are
    the ones the analyzer produced. Only the confidence changes, because the
    single thing that changed is whether the citation still holds.
    """
    reason = REASON_FOR_STATUS.get(failure.status, ReviewReason.SCHEMA_VIOLATION)
    return finding.model_copy(
        update={"confidence": Confidence.REVIEW_REQUIRED, "confidence_reason": reason}
    )
