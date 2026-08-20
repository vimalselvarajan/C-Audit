"""Part 09 adversarial test: T-09-15 (AC-09-11).

Every route by which a caller could get a ``PRIMARY`` unit compressed,
paraphrased, or truncated, tried one at a time. The point is not that
:func:`~caudit.retrieval.expand` happens not to do these things — it is that a
future caller cannot, because the model refuses to hold the state.

The routes tried here are the ones a person would actually reach for: set the
repeat count directly, attach prose instead of bytes, relabel the class and
then compress, call the compression method, or hand-build a context whose
primaries were quietly dropped to make room.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.store import SourceStore
from caudit.retrieval.context import ContextUnit, DroppedUnit, DropReason, EvidenceContext
from caudit.retrieval.policy import UnitClass, UnitRole
from tests.conftest import make_candidate, make_context_unit, retrieval_provenance

#: Every role that carries code. None of them may be compressed.
_CODE_ROLES = [role for role in UnitRole if role is not UnitRole.ANALYZER_MESSAGE]


@pytest.mark.parametrize("role", _CODE_ROLES, ids=[str(role) for role in _CODE_ROLES])
def test_no_code_role_can_be_constructed_as_compressed(role: UnitRole) -> None:
    """Route 1: set the repeat count on a code unit."""
    with pytest.raises(ValidationError, match="only secondary material may be compressed"):
        make_context_unit(role=role, occurrences=2)


@pytest.mark.parametrize("role", _CODE_ROLES, ids=[str(role) for role in _CODE_ROLES])
def test_no_code_role_can_be_given_prose_instead_of_bytes(role: UnitRole) -> None:
    """Route 2: replace the code with a summary of the code."""
    with pytest.raises(ValidationError, match="cannot carry prose"):
        make_context_unit(role=role, note="a faithful summary of what this function does")


@pytest.mark.parametrize("role", _CODE_ROLES, ids=[str(role) for role in _CODE_ROLES])
def test_relabelling_a_code_unit_as_secondary_is_refused(role: UnitRole) -> None:
    """Route 3: the two-step — reclassify, then compress the reclassified unit.

    This is the route that matters. Nothing stops a caller from *wanting* a
    smaller context; what has to be impossible is getting one by telling the
    type system that a function is an analyzer message.
    """
    honest = make_context_unit(role=role)
    payload = honest.model_dump() | {
        "unit_class": UnitClass.SECONDARY,
        "occurrences": 8,
        "note": "eight identical copies of this function",
    }
    with pytest.raises(ValidationError, match="is always"):
        ContextUnit.model_validate(payload)


@pytest.mark.parametrize("role", _CODE_ROLES, ids=[str(role) for role in _CODE_ROLES])
def test_the_compression_method_refuses_a_code_unit(role: UnitRole) -> None:
    """Route 4: the API a caller would find first."""
    with pytest.raises(ValueError, match="refusing to compress"):
        make_context_unit(role=role).collapse(5)


def test_a_secondary_unit_is_the_one_thing_that_may_be_compressed() -> None:
    """The control: the guard is a rule, not a blanket refusal."""
    message = make_context_unit(role=UnitRole.ANALYZER_MESSAGE, note="the same finding")
    collapsed = message.collapse(5)
    assert collapsed.occurrences == 5
    assert collapsed.is_compressed
    assert not collapsed.is_code


def test_a_context_cannot_be_assembled_with_its_primaries_quietly_dropped(
    tmp_path: Path,
) -> None:
    """Route 5: skip the unit type entirely and hand-build the context."""
    bundle = EvidenceBundle(SourceStore(tmp_path, revision="x"))
    primary = make_context_unit(role=UnitRole.CONTAINING_FUNCTION, token_estimate=5000)
    smaller = make_context_unit(role=UnitRole.CALLER, start_line=90, end_line=95, depth=1)

    with pytest.raises(ValidationError, match="primary units are never dropped"):
        EvidenceContext(
            candidate=make_candidate(retrieval_provenance()),
            policy_version="1",
            budget_tokens=1000,
            units=[smaller],
            total_tokens=smaller.token_estimate,
            dropped=[
                DroppedUnit(
                    unit=primary,
                    reason=DropReason.BUDGET,
                    detail="it was large and the supporting code was more interesting",
                )
            ],
            bundle=bundle,
        )


def test_a_context_cannot_understate_what_it_is_carrying(tmp_path: Path) -> None:
    """Route 6: keep the units, lie about the cost, and stay under budget."""
    bundle = EvidenceBundle(SourceStore(tmp_path, revision="x"))
    with pytest.raises(ValidationError, match="units sum to"):
        EvidenceContext(
            candidate=make_candidate(retrieval_provenance()),
            policy_version="1",
            budget_tokens=100,
            units=[make_context_unit(token_estimate=9000)],
            total_tokens=100,
            bundle=bundle,
        )
