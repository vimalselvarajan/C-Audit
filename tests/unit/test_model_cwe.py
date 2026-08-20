"""Part 02 CWE mapping tests: T-02-07, T-02-08, T-02-09."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from caudit.model.cwe import (
    ALLOWLIST,
    PROHIBITED,
    CweStatus,
    WeaknessFamily,
    classify_cwe,
    entries_for_family,
    family_of,
    is_cwe_id,
    suggest_replacement,
)
from caudit.model.evidence import Provenance
from tests.conftest import make_finding


def test_cwe_outside_the_allowlist_is_rejected(provenance: list[Provenance]) -> None:
    """T-02-07: CWE-9999 fails and the message names the allowlist."""
    with pytest.raises(ValidationError) as excinfo:
        make_finding(provenance, cwe="CWE-9999")
    assert "allowlist" in str(excinfo.value)


def test_prohibited_pillar_is_rejected_and_suggests_a_base_entry(
    provenance: list[Provenance],
) -> None:
    """T-02-08: CWE-664 on an out-of-bounds write suggests CWE-787."""
    with pytest.raises(ValidationError) as excinfo:
        make_finding(
            provenance,
            cwe="CWE-664",
            message="out-of-bounds write past the end of the buffer",
        )
    message = str(excinfo.value)
    assert "CWE-664" in message
    assert "CWE-787" in message
    assert "prohibited" in message


def test_prohibited_suggestion_is_ranked_by_context() -> None:
    write = suggest_replacement("CWE-664", "an out-of-bounds write past the end")
    use_after_free = suggest_replacement("CWE-664", "use after free of the buffer")
    assert write[0] == "CWE-787"
    assert use_after_free[0] == "CWE-416"
    # With no context the ordering is still deterministic.
    assert suggest_replacement("CWE-664", "")[0] == "CWE-787"
    assert suggest_replacement("CWE-787") == []


def test_discouraged_mapping_needs_an_explicit_rationale(
    provenance: list[Provenance],
) -> None:
    """T-02-09: rejected without a rationale, accepted with one."""
    base = make_finding(provenance)

    with pytest.raises(ValidationError, match="discouraged"):
        base.model_copy(update={"cwe": "CWE-77", "cwe_rationale": "  "}).model_validate(
            base.model_copy(update={"cwe": "CWE-77", "cwe_rationale": "  "}).model_dump(mode="json")
        )

    accepted = base.model_copy(
        update={
            "cwe": "CWE-77",
            "cwe_rationale": (
                "The sink is a shell interpreter but the injected element cannot be "
                "narrowed to an OS command, so no Base entry applies."
            ),
        }
    )
    revalidated = type(base).model_validate(accepted.model_dump(mode="json"))
    assert revalidated.cwe == "CWE-77"


def test_allowlisted_cwe_accepts_an_empty_rationale(
    provenance: list[Provenance],
) -> None:
    finding = make_finding(provenance)
    relaxed = finding.model_copy(update={"cwe_rationale": ""})
    assert type(finding).model_validate(relaxed.model_dump(mode="json")).cwe_rationale == ""


def test_every_in_scope_family_has_at_least_one_allowed_entry() -> None:
    for family in WeaknessFamily:
        allowed = [
            entry for entry in entries_for_family(family) if entry.status is CweStatus.ALLOWED
        ]
        assert allowed, f"{family} has no allowed Base/Variant entry"


def test_classification_covers_the_three_states() -> None:
    assert classify_cwe("CWE-787") is CweStatus.ALLOWED
    assert classify_cwe("CWE-77") is CweStatus.DISCOURAGED
    assert classify_cwe("CWE-664") is CweStatus.PROHIBITED
    assert classify_cwe("CWE-9999") is CweStatus.OUT_OF_SCOPE


def test_family_lookup() -> None:
    assert family_of("CWE-787") is WeaknessFamily.OUT_OF_BOUNDS
    assert family_of("CWE-9999") is None


def test_prohibited_and_allowlist_do_not_overlap() -> None:
    assert not set(PROHIBITED) & set(ALLOWLIST)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("CWE-787", True), ("CWE-", False), ("787", False), ("cwe-787", False)],
)
def test_cwe_shape_check(value: str, expected: bool) -> None:
    assert is_cwe_id(value) is expected
