"""Part 02 finding-contract tests: T-02-01, 02, 10, 11, 12, 13, 14."""

from __future__ import annotations

import json
from pathlib import PurePosixPath

import pytest
from pydantic import ValidationError

from caudit.model.evidence import EvidenceItem, EvidenceKind, Provenance
from caudit.model.finding import (
    BLOCKING_REVIEW_REASONS,
    Confidence,
    Exploitability,
    Finding,
    Impact,
    ImpactKind,
    Reachability,
    ReviewReason,
    Severity,
)
from caudit.model.source import SourceRegion, Symbol
from tests.conftest import make_evidence, make_finding, make_region

#: The spec's finding contract table, as data. Every row must be a required
#: field on Finding.
CONTRACT_FIELDS = {
    "Identity": ("finding_id", "fingerprint"),
    "Classification": ("cwe",),
    "Location": ("location", "symbol"),
    "Evidence": ("evidence",),
    "Preconditions": ("preconditions",),
    "Impact": ("impact", "reachability", "exploitability"),
    "Provenance": ("provenance",),
    "Confidence": ("confidence", "confidence_reason"),
    "Remediation": ("remediation",),
    "Maintainability impact": ("maintainability_impact",),
    "Limitations": ("limitations",),
}


def test_every_contract_row_is_a_field_on_finding() -> None:
    """T-02-01: nothing in the contract table is optional or missing."""
    fields = Finding.model_fields
    for row, names in CONTRACT_FIELDS.items():
        for name in names:
            assert name in fields, f"contract row {row!r} has no field {name!r}"

    # No catch-all: an unknown key is an error, not a silently kept extra.
    assert Finding.model_config.get("extra") == "forbid"

    # `symbol` is nullable by design (not every finding sits in a named
    # symbol) but every other contract field must be supplied explicitly.
    optional = {name for name, field in fields.items() if not field.is_required()}
    assert optional == {"symbol", "schema_version"}


def test_extra_keys_are_rejected(provenance: list[Provenance]) -> None:
    finding = make_finding(provenance)
    payload = json.loads(finding.model_dump_json())
    payload["severity_override"] = "critical"
    with pytest.raises(ValidationError, match="severity_override"):
        Finding.model_validate(payload)


def test_round_trips_through_json_without_loss(provenance: list[Provenance]) -> None:
    """T-02-02: including nested evidence and provenance."""
    finding = make_finding(provenance)
    restored = Finding.model_validate(json.loads(finding.model_dump_json()))
    assert restored == finding
    assert restored.evidence[0].provenance == finding.evidence[0].provenance


def test_empty_evidence_is_rejected(provenance: list[Provenance]) -> None:
    """T-02-10: a finding with no evidence is not representable."""
    finding = make_finding(provenance)
    payload = json.loads(finding.model_dump_json())
    payload["evidence"] = []
    with pytest.raises(ValidationError, match="evidence"):
        Finding.model_validate(payload)


def test_empty_provenance_on_evidence_is_rejected() -> None:
    """T-02-11: a claim with no producer is not representable."""
    with pytest.raises(ValidationError, match="provenance"):
        EvidenceItem(
            evidence_id="ev-whatever",
            kind=EvidenceKind.PRIMARY_CODE,
            region=make_region(),
            symbol=None,
            provenance=[],
        )


def test_empty_provenance_on_finding_is_rejected(provenance: list[Provenance]) -> None:
    finding = make_finding(provenance)
    payload = json.loads(finding.model_dump_json())
    payload["provenance"] = []
    with pytest.raises(ValidationError, match="provenance"):
        Finding.model_validate(payload)


def test_confidence_without_a_reason_is_rejected(provenance: list[Provenance]) -> None:
    """T-02-12: confidence never stands alone."""
    finding = make_finding(provenance)
    payload = json.loads(finding.model_dump_json())
    del payload["confidence_reason"]
    with pytest.raises(ValidationError, match="confidence_reason"):
        Finding.model_validate(payload)


def test_confidence_reason_must_be_from_the_closed_enum(
    provenance: list[Provenance],
) -> None:
    finding = make_finding(provenance)
    payload = json.loads(finding.model_dump_json())
    payload["confidence_reason"] = "looks about right"
    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


@pytest.mark.parametrize("reason", sorted(BLOCKING_REVIEW_REASONS))
def test_blocking_reasons_force_review_required(
    provenance: list[Provenance], reason: ReviewReason
) -> None:
    """A failed check cannot be reported as a confident finding."""
    with pytest.raises(ValidationError, match="review_required"):
        make_finding(provenance, confidence=Confidence.HIGH, confidence_reason=reason)


def test_review_required_needs_a_reason_that_says_what_is_unresolved(
    provenance: list[Provenance],
) -> None:
    with pytest.raises(ValidationError):
        make_finding(
            provenance,
            confidence=Confidence.REVIEW_REQUIRED,
            confidence_reason=ReviewReason.ALL_CITATIONS_RESOLVED,
        )


def test_impact_reachability_and_exploitability_stay_independent(
    provenance: list[Provenance],
) -> None:
    """T-02-13: a code-execution impact does not imply reachability."""
    finding = make_finding(provenance).model_copy(
        update={
            "impact": Impact(
                kind=ImpactKind.CODE_EXECUTION,
                severity=Severity.CRITICAL,
                description="Remote code execution is possible in principle.",
                evidence_supports="The write is unbounded; no path evidence exists.",
            )
        }
    )
    assert finding.impact.kind is ImpactKind.CODE_EXECUTION
    assert finding.reachability is Reachability.UNKNOWN
    assert finding.exploitability is Exploitability.UNKNOWN

    # And nothing anywhere derives one from another.
    revalidated = Finding.model_validate(json.loads(finding.model_dump_json()))
    assert revalidated.reachability is Reachability.UNKNOWN
    assert revalidated.exploitability is Exploitability.UNKNOWN


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "../x.c", "src\\x.c", "C:\\src\\x.c", "a/../../b.c"]
)
def test_hostile_paths_are_rejected_at_the_model_boundary(path: str) -> None:
    """T-02-14: absolute, parent-relative, and Windows paths all fail.

    Validated from a raw mapping, the way a hostile value actually arrives:
    out of JSON, not out of a typed constructor call.
    """
    with pytest.raises(ValidationError):
        SourceRegion.model_validate(
            {
                "path": path,
                "start_line": 1,
                "end_line": 1,
                "start_byte": 0,
                "end_byte": 1,
                "sha256": "a" * 64,
            }
        )


def test_a_finding_survives_a_round_trip_through_json(
    provenance: list[Provenance],
) -> None:
    """Serializable is only half of it — part 08 has to read the file back.

    Regression: the path validators used to return ``PurePosixPath`` objects,
    which pydantic accepts when validating Python objects and rejects when
    validating JSON. Every model here was write-only until that was fixed.
    """
    finding = make_finding(provenance, symbol=Symbol(name="copy_in", kind="function"))
    assert Finding.model_validate_json(finding.model_dump_json()) == finding

    region = make_region()
    assert SourceRegion.model_validate_json(region.model_dump_json()) == region


def test_inverted_region_bounds_are_rejected() -> None:
    with pytest.raises(ValidationError, match="precedes"):
        SourceRegion(
            path=PurePosixPath("src/x.c"),
            start_line=10,
            end_line=4,
            start_byte=0,
            end_byte=1,
            sha256="a" * 64,
        )
    with pytest.raises(ValidationError, match="precedes"):
        SourceRegion(
            path=PurePosixPath("src/x.c"),
            start_line=1,
            end_line=2,
            start_byte=90,
            end_byte=10,
            sha256="a" * 64,
        )


def test_uppercase_hash_is_rejected_so_two_spellings_cannot_diverge() -> None:
    with pytest.raises(ValidationError):
        SourceRegion(
            path=PurePosixPath("src/x.c"),
            start_line=1,
            end_line=1,
            start_byte=0,
            end_byte=1,
            sha256="A" * 64,
        )


def test_evidence_id_must_be_the_content_address(
    provenance: list[Provenance],
) -> None:
    """An id that does not address its own content is not usable as a handle."""
    item = make_evidence(provenance)
    with pytest.raises(ValidationError, match="content address"):
        item.model_copy(update={"evidence_id": "ev-0000000000000000"}).model_validate(
            json.loads(
                item.model_copy(update={"evidence_id": "ev-0000000000000000"}).model_dump_json()
            )
        )


def test_confirmed_and_review_required_have_no_merged_accessor(
    provenance: list[Provenance],
) -> None:
    """There is deliberately no `total` anywhere on the model."""
    finding = make_finding(provenance)
    assert finding.is_confirmed is True
    assert not any(name in dir(Finding) for name in ("total", "total_count", "all_findings"))


def test_symbol_requires_a_name_and_kind() -> None:
    with pytest.raises(ValidationError):
        Symbol(name="", kind="function")
    with pytest.raises(ValidationError):
        Symbol(name="f", kind="")
