"""Part 01 configuration tests: T-01-06, T-01-07, T-01-08."""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.cli.main import main
from caudit.config.loader import (
    ConfigSource,
    config_key_paths,
    load_config,
    load_config_with_sources,
)
from caudit.errors import ConfigError
from caudit.status import ExitCode


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "caudit.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_precedence_cli_beats_env_beats_file_beats_default(tmp_path: Path) -> None:
    """T-01-06: one key set at three layers resolves to the CLI value."""
    config_file = _write_config(tmp_path, 'llvm_version = "16"\n')

    from_file = load_config({}, config_file, {})
    assert from_file.llvm_version == "16"

    from_env = load_config({}, config_file, {"CAUDIT_LLVM_VERSION": "17"})
    assert from_env.llvm_version == "17"

    from_cli = load_config({"llvm_version": "18"}, config_file, {"CAUDIT_LLVM_VERSION": "17"})
    assert from_cli.llvm_version == "18"

    default = load_config({}, None, {})
    assert default.llvm_version == "18"


def test_sources_are_recorded_per_key(tmp_path: Path) -> None:
    """T-01-08: --print-config shows the effective value and its source."""
    config_file = _write_config(tmp_path, 'llvm_version = "16"\n[models]\ntriage = "from-file"\n')
    resolved = load_config_with_sources(
        {"token_budget.per_candidate": 999},
        config_file,
        {"CAUDIT_MODELS__ADJUDICATION": "from-env"},
    )
    sources = dict(resolved.sources)
    assert sources["llvm_version"] is ConfigSource.FILE
    assert sources["models.triage"] is ConfigSource.FILE
    assert sources["models.adjudication"] is ConfigSource.ENV
    assert sources["token_budget.per_candidate"] is ConfigSource.CLI
    assert sources["models.escalation"] is ConfigSource.DEFAULT

    rows = {key: (value, source) for key, value, source in resolved.render_rows()}
    assert rows["llvm_version"] == ("16", ConfigSource.FILE)
    assert rows["token_budget.per_candidate"] == ("999", ConfigSource.CLI)


def test_unknown_file_key_is_a_usage_error_naming_the_closest_match(
    tmp_path: Path,
) -> None:
    """T-01-07: 'llvm_versionn' is rejected and the real key is suggested."""
    config_file = _write_config(tmp_path, 'llvm_versionn = "18"\n')
    with pytest.raises(ConfigError) as excinfo:
        load_config({}, config_file, {})
    message = str(excinfo.value)
    assert "llvm_versionn" in message
    assert "llvm_version" in message
    assert excinfo.value.exit_code is ExitCode.USAGE


def test_unknown_file_key_through_the_cli_exits_usage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_file = _write_config(tmp_path, 'llvm_versionn = "18"\n')
    code = main(["--config", str(config_file), "doctor"])
    assert code == ExitCode.USAGE
    assert "llvm_versionn" in capsys.readouterr().err


def test_unknown_env_key_is_rejected() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config({}, None, {"CAUDIT_LLVM_VERSIONN": "18"})
    assert "CAUDIT_LLVM_VERSIONN" in str(excinfo.value)


def test_env_values_are_coerced_by_the_schema() -> None:
    config = load_config(
        {},
        None,
        {
            "CAUDIT_CLOUD_CONSENT": "true",
            "CAUDIT_TOKEN_BUDGET__PER_CANDIDATE": "5000",
            "CAUDIT_EXCLUDE_GLOBS": "a/**, b/**",
        },
    )
    assert config.cloud_consent is True
    assert config.token_budget.per_candidate == 5000
    assert config.exclude_globs == ["a/**", "b/**"]


def test_non_boolean_env_value_is_rejected() -> None:
    with pytest.raises(ConfigError, match="boolean"):
        load_config({}, None, {"CAUDIT_CLOUD_CONSENT": "perhaps"})


def test_non_integer_env_value_is_rejected() -> None:
    with pytest.raises(ConfigError, match="integer"):
        load_config({}, None, {"CAUDIT_TOKEN_BUDGET__PER_CANDIDATE": "lots"})


def test_missing_config_file_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config({}, tmp_path / "absent.toml", {})


def test_malformed_config_file_is_a_usage_error(tmp_path: Path) -> None:
    config_file = _write_config(tmp_path, "this is not = = toml\n")
    with pytest.raises(ConfigError, match="could not parse"):
        load_config({}, config_file, {})


def test_caudit_section_is_accepted(tmp_path: Path) -> None:
    config_file = _write_config(tmp_path, '[caudit]\nllvm_version = "19"\n')
    assert load_config({}, config_file, {}).llvm_version == "19"


def test_invalid_value_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config({"token_budget.per_candidate": -5}, None, {})


def test_key_paths_include_nested_leaves() -> None:
    paths = set(config_key_paths())
    assert {"llvm_version", "models", "models.triage", "token_budget.max_file_bytes"} <= paths


def test_policy_versions_are_configuration_not_constants(tmp_path: Path) -> None:
    """A report has to be able to name the policy that produced it."""
    config_file = _write_config(tmp_path, '[policy_versions]\nmatching = "7"\n')
    assert load_config({}, config_file, {}).policy_versions.matching == "7"
