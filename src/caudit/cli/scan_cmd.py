"""CLI-only normalization for scan command options."""

from __future__ import annotations

from caudit.config.loader import Config

__all__ = ["apply_scan_overrides"]


def apply_scan_overrides(
    config: Config,
    *,
    targets: list[str],
    allow_partial_coverage: bool,
    consent_cloud: bool = False,
) -> Config:
    """Fold `scan`'s own flags into the resolved configuration.

    Every flag here can only turn a setting *on*. A flag the user did not pass
    must not overwrite one they set in a configuration file — and for
    ``--consent-cloud`` that is not a convenience but the rule: an absent flag
    must never be able to withdraw a consent that was recorded deliberately,
    and it must certainly never be able to grant one.
    """
    intake = config.intake.model_dump()
    if targets:
        intake["targets"] = list(targets)
    if allow_partial_coverage:
        intake["allow_partial_coverage"] = True
    merged = config.model_dump()
    merged["intake"] = intake
    if consent_cloud:
        merged["cloud_consent"] = True
    return Config.model_validate(merged)
