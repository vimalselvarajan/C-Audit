"""Capability profiles for exact, tested Gemini model ids."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from caudit.config.schema import FLASH_LITE_MODEL_ID

__all__ = [
    "CAPABILITY_PROFILE_VERSION",
    "FLASH_LITE_MODEL_ID",
    "ModelCapabilities",
    "capabilities_for",
]

CAPABILITY_PROFILE_VERSION: Final = "1"


@dataclass(frozen=True)
class ModelCapabilities:
    """Provider features C Audit relies on for one exact stable model id."""

    model_id: str
    stable: bool
    structured_output: bool
    function_calling: bool
    context_caching: bool
    thinking_levels: frozenset[str]
    max_output_tokens: int


_PROFILES: Final[dict[str, ModelCapabilities]] = {
    FLASH_LITE_MODEL_ID: ModelCapabilities(
        model_id=FLASH_LITE_MODEL_ID,
        stable=True,
        structured_output=True,
        function_calling=True,
        context_caching=True,
        thinking_levels=frozenset({"minimal", "low", "medium", "high"}),
        max_output_tokens=65_536,
    )
}


def capabilities_for(model_id: str) -> ModelCapabilities | None:
    """Return a tested profile; unknown and mutable ids have no capabilities."""
    return _PROFILES.get(model_id)
