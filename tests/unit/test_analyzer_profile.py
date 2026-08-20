"""Part 07 profile tests: T-07-19 (AC-07-10), plus AC-07-1 at profile level.

The profile is the ruleset a report names. Two things have to be true of it:
every check says which weakness family it feeds, so part 04 can attribute a
detection; and every in-scope family has something enabled that could produce a
candidate for it, so a family that scores zero is a fact about the code rather
than an unnoticed gap in the configuration.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from caudit.analyzers.profile import (
    MAINTAINABILITY,
    CheckProfile,
    ProfileError,
    load_profile,
    parse_profile,
)
from caudit.eval.baseline import RULE_CWE_MAP
from caudit.model.cwe import WeaknessFamily, classify_cwe, family_of, is_cwe_id


@pytest.fixture
def profile() -> CheckProfile:
    return load_profile()


def _document(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "version": "1",
        "name": "test",
        "diagnostics": {"flags": ["-Wall"], "checks": []},
        "csa": {"checks": []},
        "tidy": {"checks": []},
    }
    base.update(overrides)
    return base


# ------------------------------------------------------------- validation


def test_a_check_with_no_family_annotation_is_rejected_by_name() -> None:
    """T-07-19: the error names the check, or it cannot be acted on."""
    document = _document(csa={"checks": [{"id": "core.NullDereference", "cwe": ["CWE-476"]}]})

    with pytest.raises(ProfileError) as raised:
        parse_profile(document)

    assert "core.NullDereference" in str(raised.value)
    assert "families" in str(raised.value)


def test_an_empty_family_list_is_rejected_too() -> None:
    document = _document(tidy={"checks": [{"id": "bugprone-*", "families": []}]})
    with pytest.raises(ProfileError, match="bugprone-\\*"):
        parse_profile(document)


def test_an_unknown_family_name_is_rejected_with_the_valid_set() -> None:
    document = _document(tidy={"checks": [{"id": "bugprone-*", "families": ["spelling"]}]})
    with pytest.raises(ProfileError) as raised:
        parse_profile(document)
    assert "spelling" in str(raised.value)
    assert "out_of_bounds" in str(raised.value)


def test_a_profile_with_no_version_is_rejected() -> None:
    document = _document()
    del document["version"]
    with pytest.raises(ProfileError, match="version"):
        parse_profile(document)


def test_a_malformed_cwe_id_is_rejected() -> None:
    document = _document(
        csa={"checks": [{"id": "core.X", "families": ["integer"], "cwe": ["787"]}]}
    )
    with pytest.raises(ProfileError, match="malformed CWE"):
        parse_profile(document)


def test_a_check_declared_twice_is_rejected() -> None:
    document = _document(
        tidy={
            "checks": [
                {"id": "bugprone-x", "families": ["integer"]},
                {"id": "bugprone-x", "families": ["injection"]},
            ]
        }
    )
    with pytest.raises(ProfileError, match="declared twice"):
        parse_profile(document)


def test_an_unknown_key_on_a_check_is_rejected() -> None:
    document = _document(
        tidy={"checks": [{"id": "bugprone-x", "families": ["integer"], "severity": "high"}]}
    )
    with pytest.raises(ProfileError, match="severity"):
        parse_profile(document)


def test_an_unknown_diagnostics_format_is_rejected() -> None:
    document = _document(diagnostics={"flags": [], "checks": [], "format": "xml"})
    with pytest.raises(ProfileError, match=r"'text' or 'json'"):
        parse_profile(document)


def test_loading_a_profile_that_does_not_exist_names_the_ones_that_do() -> None:
    with pytest.raises(ProfileError) as raised:
        load_profile("no-such-profile")
    assert "security" in str(raised.value)


def test_a_profile_can_be_loaded_from_a_path(tmp_path: Path) -> None:
    path = tmp_path / "custom.yaml"
    path.write_text(yaml.safe_dump(_document()), encoding="utf-8")
    assert load_profile(str(path)).version == "1"


def test_an_unreadable_profile_path_is_a_profile_error(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="could not read"):
        load_profile(str(tmp_path / "missing.yaml"))


def test_a_profile_that_is_not_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("version: [unclosed\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="not valid YAML"):
        load_profile(str(path))


# ------------------------------------------------------ the shipped profile


def test_the_shipped_profile_covers_every_in_scope_weakness_family(
    profile: CheckProfile,
) -> None:
    """AC-07-1 at the level this part controls.

    Whether a *fixture* yields a candidate depends on the code in it; whether
    the profile can produce one for a family is a property of this file, and it
    is the half that must never silently regress.
    """
    assert profile.families_covered() == set(WeaknessFamily)


def test_every_check_in_the_shipped_profile_is_annotated(profile: CheckProfile) -> None:
    for check in profile.checks:
        assert check.families, check.id


def test_every_mapped_cwe_is_well_formed_and_agrees_with_its_family(
    profile: CheckProfile,
) -> None:
    """An annotation that contradicts its own CWE would score in two places."""
    for check in profile.checks:
        annotated = set(check.weakness_families())
        for cwe in check.cwe:
            assert is_cwe_id(cwe), f"{check.id}: {cwe}"
            family = family_of(cwe)
            if family is None:
                # Accurate but outside the MVP allowlist. The candidate is
                # still produced and routed to review by part 11.
                assert classify_cwe(cwe).value == "out_of_scope", f"{check.id}: {cwe}"
                continue
            assert family in annotated, f"{check.id} maps {cwe} ({family}) but is not annotated"


def test_the_maintainability_slice_never_claims_a_weakness_family(
    profile: CheckProfile,
) -> None:
    """Security-relevant maintainability signals are not vulnerability claims."""
    for check in profile.checks:
        if check.families == (MAINTAINABILITY,):
            assert check.cwe == (), check.id


def test_the_profile_agrees_with_part_fours_baseline_table(profile: CheckProfile) -> None:
    """Baseline numbers stay comparable only if one rule keeps one meaning.

    Part 04 measured the analyzer-only floor with its own rule table. Where
    both know a rule, they must agree, or an M1-vs-M0 comparison would be
    measuring the mapping change rather than the pipeline.
    """
    for rule, expected in RULE_CWE_MAP.items():
        mapped = profile.cwe_for(rule)
        if not mapped:
            continue  # the profile leaves it unmapped; nothing to disagree with
        assert set(mapped) == set(expected), rule


def test_the_tidy_checks_argument_disables_everything_first(profile: CheckProfile) -> None:
    argument = profile.tidy_checks_argument()
    assert argument.startswith("-*,")
    assert "bugprone-*" in argument
    # Disabled entries are negated after the enablements, in order.
    assert argument.index("bugprone-*") < argument.index("-bugprone-easily-swappable-parameters")


def test_csa_checkers_are_named_individually_not_by_package(profile: CheckProfile) -> None:
    """Naming each one is what lets part 04 track an alpha checker's noise."""
    checkers = profile.csa_checkers()
    assert "core.NullDereference" in checkers
    assert not any(checker.endswith("*") for checker in checkers)
    assert any(checker.startswith("alpha.") for checker in checkers)


def test_lookup_reconciles_the_two_spellings_of_one_check(profile: CheckProfile) -> None:
    """One warning, one CWE, whichever producer surfaced it."""
    assert profile.cwe_for("unix.Malloc") == profile.cwe_for("clang-analyzer-unix.Malloc")
    assert profile.cwe_for("-Wformat-security") == profile.cwe_for(
        "clang-diagnostic-format-security"
    )


def test_an_unknown_rule_does_not_inherit_a_glob_it_has_no_claim_to(
    profile: CheckProfile,
) -> None:
    assert profile.lookup("totally-unknown-rule") is None
    # But a check inside an enabled family's glob does match it, with no CWE.
    inside = profile.lookup("bugprone-future-check-2030")
    assert inside is not None and inside.id == "bugprone-*" and inside.cwe == ()
