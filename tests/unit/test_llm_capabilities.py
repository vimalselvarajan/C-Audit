"""Exact Gemini capability profiles."""

from caudit.llm.capabilities import (
    CAPABILITY_PROFILE_VERSION,
    FLASH_LITE_MODEL_ID,
    capabilities_for,
)


def test_the_stable_flash_lite_profile_names_every_required_capability() -> None:
    profile = capabilities_for(FLASH_LITE_MODEL_ID)

    assert profile is not None
    assert profile.stable
    assert profile.structured_output
    assert profile.function_calling
    assert profile.context_caching
    assert profile.thinking_levels == {"minimal", "low", "medium", "high"}
    assert profile.max_output_tokens == 65_536
    assert CAPABILITY_PROFILE_VERSION == "1"


def test_mutable_and_unknown_ids_have_no_inferred_capabilities() -> None:
    assert capabilities_for("gemini-flash-lite-latest") is None
    assert capabilities_for("future-model") is None
