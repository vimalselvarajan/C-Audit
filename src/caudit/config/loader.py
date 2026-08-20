"""Configuration loading, validation, and precedence resolution."""

from __future__ import annotations

import difflib
import tomllib
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, ValidationError

from caudit.config.schema import (
    AnalyzerConfig,
    Config,
    ConfigSource,
    IndexConfig,
    IntakeConfig,
    LLMConfig,
    ModelTierConfig,
    PolicyVersions,
    PricingConfig,
    RetrievalConfig,
    RetrievalVariantName,
    TierPricing,
    TokenBudget,
)
from caudit.errors import ConfigError

__all__ = [
    "AnalyzerConfig",
    "Config",
    "ConfigSource",
    "IndexConfig",
    "IntakeConfig",
    "LLMConfig",
    "ModelTierConfig",
    "PolicyVersions",
    "PricingConfig",
    "ResolvedConfig",
    "RetrievalConfig",
    "RetrievalVariantName",
    "TierPricing",
    "TokenBudget",
    "config_key_paths",
    "load_config",
    "load_config_with_sources",
]

ENV_PREFIX: Final = "CAUDIT_"
ENV_NEST: Final = "__"


def config_key_paths(model: type[BaseModel] = Config, prefix: str = "") -> list[str]:
    """Every dotted key the config accepts, for error messages and env parsing."""
    paths: list[str] = []
    for name, field in model.model_fields.items():
        dotted = f"{prefix}{name}"
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            paths.append(dotted)
            paths.extend(config_key_paths(annotation, f"{dotted}."))
        else:
            paths.append(dotted)
    return paths


class ResolvedConfig(BaseModel):
    """The effective config plus where each leaf value came from."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    config: Config
    sources: dict[str, ConfigSource]
    config_file: Path | None = None

    def render_rows(self) -> list[tuple[str, str, str]]:
        """``(key, value, source)`` rows for ``--print-config``.

        Only configuration is rendered. Secrets are not configuration: the
        Gemini API key is read from the environment at call time and is not a
        field of :class:`Config`, so it cannot appear here.
        """
        rows: list[tuple[str, str, str]] = []
        for key, value in _walk(self.config.model_dump(mode="json")):
            rows.append((key, _format_value(value), self.sources.get(key, ConfigSource.DEFAULT)))
        return rows


def _walk(value: object, prefix: str = "") -> Iterator[tuple[str, object]]:
    if isinstance(value, dict):
        for key, sub in value.items():
            yield from _walk(sub, f"{prefix}{key}.")
        return
    yield prefix.rstrip("."), value


def _format_value(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _flatten(mapping: Mapping[str, object], prefix: str = "") -> dict[str, object]:
    flat: dict[str, object] = {}
    for key, value in mapping.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, f"{dotted}."))
        else:
            flat[dotted] = value
    return flat


def _unflatten(flat: Mapping[str, object]) -> dict[str, Any]:
    nested: dict[str, Any] = {}
    for dotted, value in flat.items():
        parts = dotted.split(".")
        cursor = nested
        for part in parts[:-1]:
            branch = cursor.setdefault(part, {})
            if not isinstance(branch, dict):  # pragma: no cover - guarded by key check
                raise ConfigError(f"configuration key '{dotted}' conflicts with a scalar value")
            cursor = branch
        cursor[parts[-1]] = value
    return nested


def _reject_unknown(keys: Mapping[str, object], origin: str) -> None:
    valid = set(config_key_paths())
    for key in keys:
        if key in valid:
            continue
        close = difflib.get_close_matches(key, sorted(valid), n=1, cutoff=0.6)
        suggestion = f" Did you mean '{close[0]}'?" if close else ""
        raise ConfigError(
            f"unknown configuration key '{key}' in {origin}.{suggestion}",
            hint="Run 'caudit --print-config' to see every accepted key.",
        )


def _read_file(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ConfigError(f"configuration file not found: {path}")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"could not parse configuration file {path}: {exc}") from exc
    # Accept both a bare table and a [caudit] section.
    section = raw.get("caudit", raw)
    if not isinstance(section, dict):
        raise ConfigError(f"[caudit] in {path} must be a table")
    return _flatten(section)


def _coerce_env(key: str, value: str) -> object:
    """Environment values are strings; the schema says what they mean."""
    field = _leaf_field(key)
    annotation = field.annotation if field is not None else None
    if annotation is bool:
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        raise ConfigError(f"{ENV_PREFIX}{key.upper().replace('.', ENV_NEST)} must be a boolean")
    if annotation is int:
        try:
            return int(value)
        except ValueError as exc:
            raise ConfigError(
                f"{ENV_PREFIX}{key.upper().replace('.', ENV_NEST)} must be an integer"
            ) from exc
    if annotation is float:
        try:
            return float(value)
        except ValueError as exc:
            raise ConfigError(
                f"{ENV_PREFIX}{key.upper().replace('.', ENV_NEST)} must be a number"
            ) from exc
    if annotation is not None and getattr(annotation, "__origin__", None) is list:
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


def _leaf_field(dotted: str) -> Any:
    model: type[BaseModel] = Config
    parts = dotted.split(".")
    for part in parts[:-1]:
        field = model.model_fields.get(part)
        annotation = None if field is None else field.annotation
        if not (isinstance(annotation, type) and issubclass(annotation, BaseModel)):
            return None
        model = annotation
    return model.model_fields.get(parts[-1])


def _read_env(env: Mapping[str, str]) -> dict[str, object]:
    valid = set(config_key_paths())
    by_env_name = {key.upper().replace(".", ENV_NEST): key for key in valid}
    flat: dict[str, object] = {}
    for name, value in env.items():
        if not name.startswith(ENV_PREFIX):
            continue
        suffix = name[len(ENV_PREFIX) :]
        key = by_env_name.get(suffix)
        if key is None:
            candidates = sorted(by_env_name)
            close = difflib.get_close_matches(suffix, candidates, n=1, cutoff=0.6)
            suggestion = f" Did you mean '{ENV_PREFIX}{close[0]}'?" if close else ""
            raise ConfigError(
                f"unknown configuration key '{name}' in the environment.{suggestion}",
                hint="Run 'caudit --print-config' to see every accepted key.",
            )
        flat[key] = _coerce_env(key, value)
    return flat


def load_config_with_sources(
    cli_overrides: Mapping[str, object],
    config_file: Path | None,
    env: Mapping[str, str],
) -> ResolvedConfig:
    """Resolve every layer and record which one won for each key."""
    layers: list[tuple[ConfigSource, dict[str, object]]] = []

    if config_file is not None:
        file_values = _read_file(config_file)
        _reject_unknown(file_values, str(config_file))
        layers.append((ConfigSource.FILE, file_values))

    layers.append((ConfigSource.ENV, _read_env(env)))

    cli_values = {key: value for key, value in cli_overrides.items() if value is not None}
    _reject_unknown(cli_values, "command-line options")
    layers.append((ConfigSource.CLI, cli_values))

    merged: dict[str, object] = {}
    sources: dict[str, ConfigSource] = {}
    for source, values in layers:
        for key, value in values.items():
            merged[key] = value
            sources[key] = source

    try:
        config = Config.model_validate(_unflatten(merged))
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration:\n{exc}") from exc

    # Keys nobody overrode came from the packaged defaults.
    for key, _ in _walk(config.model_dump(mode="json")):
        sources.setdefault(key, ConfigSource.DEFAULT)
    return ResolvedConfig(config=config, sources=sources, config_file=config_file)


def load_config(
    cli_overrides: Mapping[str, object],
    config_file: Path | None,
    env: Mapping[str, str],
) -> Config:
    """Precedence: CLI > env (``CAUDIT_*``) > config file > packaged defaults."""
    return load_config_with_sources(cli_overrides, config_file, env).config
