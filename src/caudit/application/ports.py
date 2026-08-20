"""Narrow dependency ports used by application use cases."""

from __future__ import annotations

from typing import Protocol

from caudit.llm.consent import ConsentDecision
from caudit.llm.provider import LLMProvider


class ConsentAwareProviderFactory(Protocol):
    """Create the only network-capable dependency from an explicit consent decision."""

    def __call__(self, consent: ConsentDecision) -> LLMProvider:
        """Return a provider that retains the consent decision at construction."""
