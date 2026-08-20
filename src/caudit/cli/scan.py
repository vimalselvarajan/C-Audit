"""CLI compatibility facade for the scan application use case."""

from caudit.application.providers import gemini_provider_factory
from caudit.application.scan import ScanResult, run_scan

__all__ = ["ScanResult", "gemini_provider_factory", "run_scan"]
