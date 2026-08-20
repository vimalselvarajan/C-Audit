"""The three supporting modules, exercised directly.

The gate tests reach these through a whole verification, which is the right way
to know that the parts fit together and the wrong way to know that a mapping is
exhaustive or an ordering is total. These are the second kind of question.
"""

from __future__ import annotations

import random

import pytest

from caudit.evidence.resolver import (
    REASON_FOR_STATUS,
    Citation,
    Resolution,
    ResolutionStatus,
)
from caudit.model.candidate import Candidate
from caudit.model.cwe import ALLOWLIST, CweStatus, WeaknessFamily, classify_cwe, family_of
from caudit.model.evidence import Producer, Provenance
from caudit.model.finding import BLOCKING_REVIEW_REASONS, ReviewReason
from caudit.model.source import SourceRegion
from caudit.verify.cwe_check import (
    cited_text,
    precondition_failures,
    preconditions_for,
    status_failure,
    usable_cwe,
)
from caudit.verify.reasons import Failure, ordered, reason_for, summarize


def _resolution(status: ResolutionStatus, *, citation: Citation | None = None) -> Resolution:
    return Resolution(
        status=status,
        citation=citation or Citation(path="src/a.c", start_line=1),
        detail="because",
    )


# ------------------------------------------------------------------- ordering


def test_every_review_reason_has_a_rank() -> None:
    """An unranked member would sort by name — deterministic, but arbitrary.

    The fallback exists so a new member cannot make the gate non-deterministic
    before anyone remembers to rank it. This test is what makes sure nobody
    relies on the fallback.
    """
    from caudit.verify.reasons import _RANK

    assert set(_RANK) == set(ReviewReason)
    assert len(set(_RANK.values())) == len(_RANK), "two reasons share a rank"


def test_ordering_is_total_and_independent_of_input_order() -> None:
    reasons = list(ReviewReason)
    expected = ordered(reasons)
    rng = random.Random(11)
    for _ in range(25):
        shuffled = reasons[:]
        rng.shuffle(shuffled)
        assert ordered(shuffled) == expected


def test_ordering_deduplicates() -> None:
    doubled = [ReviewReason.HASH_MISMATCH, ReviewReason.HASH_MISMATCH]
    assert ordered(doubled) == [ReviewReason.HASH_MISMATCH]


def test_an_unranked_reason_sorts_last_rather_than_crashing() -> None:
    """Simulated by ranking nothing: the fallback must be a sort key, not a raise."""
    from caudit.verify import reasons as module

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(module, "_RANK", {})
        result = module.ordered([ReviewReason.HASH_MISMATCH, ReviewReason.ANALYZER_ONLY])
    assert result == sorted(result, key=str)


def test_summaries_read_in_the_same_order_as_the_reasons() -> None:
    """A reader matching the third reason to the third line must be right."""
    failures = [
        Failure(reason=ReviewReason.ASSUMPTIONS_UNSTATED, detail="no assumptions"),
        Failure(reason=ReviewReason.CITATION_UNRESOLVED, detail="invented id"),
        Failure(reason=ReviewReason.HASH_MISMATCH, detail="bytes differ"),
    ]
    lines = summarize(failures)
    assert [line.split(":")[0] for line in lines] == [
        str(reason) for reason in ordered(f.reason for f in failures)
    ]


def test_identical_failures_are_summarized_once() -> None:
    same = Failure(reason=ReviewReason.HASH_MISMATCH, detail="bytes differ", subject="x")
    assert len(summarize([same, same])) == 1


def test_a_failure_describes_its_subject_when_it_has_one() -> None:
    assert "(x)" in Failure(ReviewReason.HASH_MISMATCH, "d", "x").describe()
    assert "()" not in Failure(ReviewReason.HASH_MISMATCH, "d").describe()


# ------------------------------------------------------- the resolver mapping


def test_every_failing_status_maps_to_a_blocking_reason() -> None:
    """A status that mapped to a non-blocking reason could be confirmed."""
    assert set(REASON_FOR_STATUS) == set(ResolutionStatus) - {ResolutionStatus.OK}
    assert set(REASON_FOR_STATUS.values()) <= BLOCKING_REVIEW_REASONS


def test_an_edge_claim_that_fails_reads_as_an_edge_failure() -> None:
    """The resolver reports both faults as ``SYMBOL_NOT_FOUND``; only the caller knows."""
    edge = Citation(caller="a", callee="b")
    assert reason_for(_resolution(ResolutionStatus.SYMBOL_NOT_FOUND, citation=edge)) is (
        ReviewReason.CALL_EDGE_UNRESOLVED
    )
    assert reason_for(_resolution(ResolutionStatus.SYMBOL_NOT_FOUND)) is (
        ReviewReason.SYMBOL_UNRESOLVED
    )


def test_an_edge_claim_failing_on_its_region_is_a_location_failure() -> None:
    """An edge citation that also names a file can fail on the file."""
    edge = Citation(path="src/a.c", start_line=1, caller="a", callee="b")
    assert reason_for(_resolution(ResolutionStatus.MISSING_FILE, citation=edge)) is (
        ReviewReason.MISSING_FILE
    )


def test_an_id_the_bundle_never_issued_is_a_citation_failure() -> None:
    assert reason_for(_resolution(ResolutionStatus.UNKNOWN_EVIDENCE_ID)) is (
        ReviewReason.CITATION_UNRESOLVED
    )


def test_an_unmapped_status_falls_back_to_a_blocking_reason() -> None:
    """Defensive: a status added without a mapping must not become ``ok``."""
    from caudit.verify import reasons as module

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(module, "REASON_FOR_STATUS", {})
        assert module.reason_for(_resolution(ResolutionStatus.MISSING_FILE)) is (
            ReviewReason.SCHEMA_VIOLATION
        )


# ------------------------------------------------------------ CWE status rules


def test_every_allowlisted_entry_can_be_carried() -> None:
    """The gate must not refuse a CWE that part 02's ``Finding`` would accept."""
    for cwe, entry in ALLOWLIST.items():
        rationale = "explained" if entry.status is CweStatus.DISCOURAGED else ""
        assert status_failure(cwe, rationale) is None, cwe


def test_a_confirmation_with_no_cwe_is_refused_by_the_status_check() -> None:
    """Part 10's schema already refuses this; the gate does not depend on that.

    Two checks of one rule is the pattern the whole project uses, and here it
    matters because an ``Adjudication`` can also arrive from a cache or a
    recording rather than from the loop that validated it.
    """
    failure = status_failure(None, "")
    assert failure is not None
    assert failure.reason is ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE
    assert "without naming a weakness" in failure.detail


def test_a_prohibited_entry_is_refused_with_ranked_suggestions() -> None:
    failure = status_failure("CWE-664", "a use-after-free of the released buffer")
    assert failure is not None
    assert failure.reason is ReviewReason.CWE_MAPPING_REJECTED
    assert "CWE-416" in failure.detail


def test_a_prohibited_entry_with_no_replacements_still_names_the_rule() -> None:
    failure = status_failure("CWE-693", "")
    assert failure is not None
    assert "Base or Variant entry" in failure.detail


# ---------------------------------------------------------- CWE preconditions


def test_every_in_scope_family_has_preconditions() -> None:
    """A family with none would confirm any argument that named it."""
    for family in WeaknessFamily:
        entry = next(cwe for cwe, e in ALLOWLIST.items() if e.family is family)
        assert preconditions_for(entry), family


def test_an_out_of_scope_entry_has_no_preconditions() -> None:
    """Its status check fires first; inventing rules would double-report."""
    assert preconditions_for("CWE-327") == ()


@pytest.mark.parametrize(
    ("cwe", "text"),
    [
        ("CWE-416", "local_free(buffer->data);"),
        ("CWE-415", "buffer_release(&scratch);"),
        ("CWE-787", "frame->buf[index] = src[index];"),
        ("CWE-787", "memcpy(dst, src, len);"),
        ("CWE-125", "return text[offset];"),
        ("CWE-476", "return head->magic;"),
        ("CWE-190", "total += values[index];"),
        ("CWE-401", "scratch.data = local_alloc(length);"),
        ("CWE-134", "printf(user_supplied);"),
    ],
)
def test_evidence_that_satisfies_a_family(cwe: str, text: str) -> None:
    assert precondition_failures(cwe, text) == []


@pytest.mark.parametrize(
    ("cwe", "text"),
    [
        ("CWE-416", "int total = a + b;"),
        ("CWE-787", "struct Frame { char buf[16]; int used; };"),
        ("CWE-476", "int total = 1;"),
        ("CWE-401", "return status;"),
        ("CWE-134", "int len = strlen(name);"),
    ],
)
def test_evidence_that_does_not(cwe: str, text: str) -> None:
    failures = precondition_failures(cwe, text)
    assert [failure.reason for failure in failures] == [ReviewReason.EVIDENCE_DOES_NOT_SUPPORT_CWE]
    assert cwe in failures[0].detail


def test_the_write_and_read_variants_of_one_family_differ() -> None:
    """The split is the reason ``_BY_CWE`` exists at all."""
    declaration = "struct Frame { char buf[16]; int used; };"
    assert precondition_failures("CWE-787", declaration)
    assert precondition_failures("CWE-125", declaration) == []


def test_cited_text_decodes_the_way_the_prompt_decoded_it() -> None:
    """Matching a different document from the one the model read would be useless."""
    assert cited_text([b"a\xffb", b"c"]) == "a�b\nc"


# --------------------------------------------------------------- CWE fallback


def _candidate(*cwes: str) -> Candidate:
    return Candidate.create(
        region=SourceRegion(
            path="src/a.c", start_line=1, end_line=1, start_byte=0, end_byte=1, sha256="0" * 64
        ),
        message="something happened",
        provenance=[
            Provenance(producer=Producer.CSA, tool_name="clang-static-analyzer", tool_version="18")
        ],
        suggested_cwe=list(cwes),
    )


def test_a_carriable_proposal_is_kept() -> None:
    assert usable_cwe("CWE-416", _candidate("CWE-787"), fallback="CWE-908") == "CWE-416"


def test_a_discouraged_proposal_is_still_carriable() -> None:
    """The rationale is what ``status_failure`` checks; carrying it is separate."""
    assert classify_cwe("CWE-119") is CweStatus.DISCOURAGED
    assert usable_cwe("CWE-119", _candidate(), fallback="CWE-908") == "CWE-119"


def test_a_refused_proposal_falls_back_to_the_analyzers_classification() -> None:
    assert usable_cwe("CWE-327", _candidate("CWE-787"), fallback="CWE-908") == "CWE-787"


def test_a_candidate_with_no_usable_cwe_falls_back_further() -> None:
    """A review item still has to name something part 02 will accept."""
    carried = usable_cwe("CWE-327", _candidate("CWE-664"), fallback="CWE-908")
    assert carried == "CWE-908"
    assert family_of(carried) is not None


def test_no_proposal_at_all_uses_the_candidates_own(tmp_path: object) -> None:
    assert usable_cwe(None, _candidate("CWE-125"), fallback="CWE-908") == "CWE-125"


# ------------------------------------------------------------ claim ceilings


def _claim_signals(**overrides: bool) -> dict[str, bool]:
    signals = {"control_flow": False, "code": False, "upstream": False}
    signals.update(overrides)
    return signals


def test_the_exploitability_ceiling_is_graded_by_what_was_cited() -> None:
    """ "Above ``unlikely`` requires attacker-input evidence", plus one refinement.

    ``demonstrated`` additionally needs the traced path. That is stricter than
    the plan's sentence rather than looser, and it is what keeps the value
    reachable at all instead of being a claim the gate can never allow.
    """
    from caudit.model.finding import Exploitability, Reachability
    from caudit.verify.claims import _exploitability_ceiling, _reachability_ceiling

    assert _exploitability_ceiling(_claim_signals()) is Exploitability.UNLIKELY
    assert _exploitability_ceiling(_claim_signals(upstream=True)) is Exploitability.PLAUSIBLE
    assert (
        _exploitability_ceiling(_claim_signals(upstream=True, control_flow=True))
        is Exploitability.DEMONSTRATED
    )

    assert _reachability_ceiling(_claim_signals()) is Reachability.UNKNOWN
    assert _reachability_ceiling(_claim_signals(code=True)) is Reachability.ARGUED
    assert _reachability_ceiling(_claim_signals(control_flow=True)) is Reachability.DEMONSTRATED


def test_the_downgrade_explanation_names_which_evidence_was_missing() -> None:
    """Two different absences, two different things for a reviewer to go find."""
    from caudit.verify.claims import _exploitability_detail, _reachability_detail

    assert "no code was cited" in _reachability_detail(_claim_signals())
    assert "no control-flow evidence" in _reachability_detail(_claim_signals(code=True))
    assert "nothing upstream" in _exploitability_detail(_claim_signals())
    assert "no traced path" in _exploitability_detail(_claim_signals(upstream=True))
