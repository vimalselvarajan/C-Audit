"""Application-owned construction of consent-aware provider adapters."""

from __future__ import annotations

from caudit.llm.consent import ConsentDecision
from caudit.llm.provider import LLMProvider


def gemini_provider_factory(consent: ConsentDecision) -> LLMProvider:
    """Create Gemini only after the caller established explicit cloud consent."""
    from caudit.llm.gemini import GeminiProvider

    return GeminiProvider(consent=consent)
