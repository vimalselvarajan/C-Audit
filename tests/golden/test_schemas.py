"""Part 02 schema tests: T-02-15, T-02-16, T-02-17."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel, Field

from caudit.application.schema_export import (
    EXPORTED_MODELS,
    SCHEMA_DIR,
    check_drift,
    export_all,
    render_schema,
    structured_output_violations,
)
from caudit.model.finding import SCHEMA_VERSION, Finding


def test_committed_schemas_match_a_fresh_export_byte_for_byte() -> None:
    """T-02-15."""
    drifted = check_drift()
    assert not drifted, "\n".join(d.message() for d in drifted)


def test_every_exported_model_has_a_committed_file() -> None:
    for path in export_all():
        assert path.is_file(), f"{path.name} is not committed"


def test_drift_check_names_the_schema_version_bump(tmp_path: Path) -> None:
    """T-02-16: simulate a model change with no version bump."""
    # Write today's schemas into a scratch directory, then perturb one so the
    # committed text no longer matches what the models produce.
    for path, text in export_all(tmp_path).items():
        path.write_text(text, encoding="utf-8")
    victim = tmp_path / "finding.schema.json"
    payload = json.loads(victim.read_text(encoding="utf-8"))
    payload["properties"]["severity_shortcut"] = {"type": "string"}
    victim.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", "utf-8")

    drifted = check_drift(tmp_path)
    assert [d.path.name for d in drifted] == ["finding.schema.json"]
    message = drifted[0].message()
    assert "SCHEMA_VERSION" in message
    assert SCHEMA_VERSION in message
    assert "make schemas" in message


def test_missing_committed_schema_is_reported_as_drift(tmp_path: Path) -> None:
    drifted = check_drift(tmp_path)
    # Every rendered schema, models and derived response schemas alike: the
    # flattened shape a provider is handed is committed for the same reason
    # the models are.
    assert len(drifted) == len(export_all())
    assert len(drifted) > len(EXPORTED_MODELS)
    assert all("missing" in d.message() for d in drifted)


def test_schema_export_is_deterministic() -> None:
    first = render_schema(Finding, "finding")
    second = render_schema(Finding, "finding")
    assert first == second
    assert first.endswith("\n")
    assert json.loads(first)["x-caudit-schema-version"] == SCHEMA_VERSION


def test_exported_finding_schema_is_usable_as_a_structured_output_schema() -> None:
    """T-02-17: offline shape check for unsupported JSON Schema constructs."""
    schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
    violations = structured_output_violations(schema)
    assert violations == []


def test_shape_checker_actually_detects_unsupported_constructs() -> None:
    """A checker that never fires would pass T-02-17 vacuously."""

    class Nested(BaseModel):
        value: str

    class WithOneOf(BaseModel):
        choice: str = Field(json_schema_extra={"oneOf": [{"type": "string"}]})
        nested: Nested

    violations = structured_output_violations(WithOneOf.model_json_schema())
    assert any("oneOf" in violation for violation in violations)


@pytest.mark.parametrize("name", sorted(EXPORTED_MODELS))
def test_each_schema_declares_its_identity(name: str) -> None:
    schema = json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
    assert schema["$id"].endswith(f"{name}.schema.json")
    assert schema["$schema"].startswith("https://json-schema.org/draft/")
