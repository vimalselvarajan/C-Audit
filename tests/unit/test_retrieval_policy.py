"""Part 09 policy tests: T-09-21, T-09-22.

Covers AC-09-8 and the part 13 dependency that made these necessary: an
ablation can only vary a factor a run can be configured with, so
``ExpansionPolicy.from_config`` reading only the version was a silent ceiling
on what part 13 could measure.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from caudit.config.loader import Config, RetrievalVariantName, load_config
from caudit.retrieval.policy import DEFAULT_POLICY, ExpansionPolicy, RetrievalVariant

# ------------------------------------------------------------------ T-09-22


def test_every_depth_knob_survives_the_trip_through_configuration() -> None:
    """T-09-22: a policy built from config is the config, not the defaults.

    Each knob is given a value the default does not have, so a field the
    conversion forgot shows up as its default rather than passing by accident.
    """
    config = Config.model_validate(
        {
            "policy_versions": {"retrieval": "7"},
            "retrieval": {
                "caller_depth": 5,
                "callee_depth": 3,
                "include_cleanup_paths": False,
                "include_global_decls": False,
                "max_units": 11,
                "type_closure_depth": 4,
                "variant": "flat_window",
                "flat_window_lines": 12,
            },
        }
    )
    policy = ExpansionPolicy.from_config(config)

    assert policy.version == "7"
    assert policy.caller_depth == 5
    assert policy.callee_depth == 3
    assert policy.include_cleanup_paths is False
    assert policy.include_global_decls is False
    assert policy.max_units == 11
    assert policy.type_closure_depth == 4
    assert policy.variant is RetrievalVariant.FLAT_WINDOW
    assert policy.flat_window_lines == 12

    # Every one of those differs from the packaged default, so the assertions
    # above cannot be satisfied by a conversion that returned the defaults.
    for field in (
        "caller_depth",
        "callee_depth",
        "include_cleanup_paths",
        "include_global_decls",
        "max_units",
        "type_closure_depth",
        "variant",
        "flat_window_lines",
    ):
        assert getattr(policy, field) != getattr(DEFAULT_POLICY, field), field


def test_the_default_configuration_produces_the_default_policy() -> None:
    """Configuration nobody touched must not quietly change what a scan does."""
    policy = ExpansionPolicy.from_config(Config())

    assert policy.model_dump() == DEFAULT_POLICY.model_dump()
    assert policy.variant is RetrievalVariant.STRUCTURAL


def test_the_config_literal_and_the_variant_enum_cannot_drift() -> None:
    """The price of spelling the variants twice, paid here.

    ``config.loader`` cannot import the enum — ``retrieval.policy`` reads
    ``Config``, so the dependency runs one way — and a literal that gained a
    value the enum lacks would accept configuration nothing implements.
    """
    assert set(get_args(RetrievalVariantName)) == {member.value for member in RetrievalVariant}


def test_an_unknown_variant_is_refused_at_configuration_load() -> None:
    """A bad value fails before a scan starts, not half way through one."""
    with pytest.raises(Exception) as caught:
        load_config({"retrieval.variant": "semantic-ish"}, None, {})

    assert "variant" in str(caught.value)


# ------------------------------------------------------------------ T-09-21


def test_the_semantic_variant_is_refused_by_name() -> None:
    """T-09-21: the variant is named so a grid can ask for it and be told no.

    Accepting it and running structural retrieval underneath would file
    structural numbers under a semantic label, which is worse than not having
    the variant at all.
    """
    with pytest.raises(ValidationError) as caught:
        ExpansionPolicy(variant=RetrievalVariant.STRUCTURAL_PLUS_SEMANTIC)

    message = str(caught.value)
    assert "not implemented" in message
    assert "structural_plus_semantic" in message


def test_the_semantic_variant_is_refused_through_configuration_too() -> None:
    """The refusal is on the type, so every route into it is closed."""
    config = Config.model_validate({"retrieval": {"variant": "structural_plus_semantic"}})

    with pytest.raises(ValidationError):
        ExpansionPolicy.from_config(config)
