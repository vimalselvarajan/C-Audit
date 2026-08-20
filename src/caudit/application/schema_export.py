"""Export the domain models as JSON Schema, and detect drift.

The same definitions constrain Gemini's output (part 10) and validate it
(part 11), so they are committed to the repository rather than generated at
runtime. ``check_drift`` compares a fresh export against what is committed;
CI fails on any difference unless ``SCHEMA_VERSION`` moved in the same
change.

A shape check is included for the structured-output constraint: Gemini's
response schemas do not accept every JSON Schema construct, so part 10 needs
to know offline whether the exported schema is usable as-is.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel

from caudit.llm.schema import adjudication_response_schema, triage_response_schema
from caudit.model.adjudication import Adjudication, TriageResult
from caudit.model.candidate import Candidate
from caudit.model.evidence import EvidenceItem
from caudit.model.finding import SCHEMA_VERSION, Finding
from caudit.model.manifest import RunManifest

__all__ = [
    "DERIVED_SCHEMAS",
    "EXPORTED_MODELS",
    "SCHEMA_DIR",
    "SchemaDrift",
    "check_drift",
    "export_all",
    "render_derived",
    "render_schema",
    "structured_output_violations",
]

SCHEMA_DIR: Final = Path(__file__).resolve().parents[3] / "schemas"

EXPORTED_MODELS: Final[dict[str, type[BaseModel]]] = {
    "adjudication": Adjudication,
    "candidate": Candidate,
    "evidence-item": EvidenceItem,
    "finding": Finding,
    "run-manifest": RunManifest,
    "triage-result": TriageResult,
}

#: Schemas that are *derived* rather than rendered from a model: the shapes a
#: provider is actually handed. They are committed for the same reason the
#: models are — the flattening is a mapping, and an undetected change to it
#: would send a different contract than the one that was reviewed.
DERIVED_SCHEMAS: Final[dict[str, Callable[[], Mapping[str, Any]]]] = {
    "adjudication-response": adjudication_response_schema,
    "triage-response": triage_response_schema,
}

#: Constructs Gemini's structured-output schemas do not accept. Checked
#: offline so part 10 never discovers the problem in a live call.
_UNSUPPORTED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "oneOf",
        "not",
        "patternProperties",
        "dependentSchemas",
        "if",
        "then",
        "else",
        "prefixItems",
        "unevaluatedProperties",
        "additionalItems",
        "contains",
    }
)


def render_schema(model: type[BaseModel], name: str) -> str:
    """Deterministic JSON text for one model's schema.

    Sorted keys and a trailing newline, so a byte-for-byte comparison is a
    meaningful test rather than a formatting lottery.
    """
    schema = model.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://caudit.dev/schemas/{name}.schema.json"
    schema["x-caudit-schema-version"] = SCHEMA_VERSION
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_derived(schema: Mapping[str, Any], name: str) -> str:
    """Deterministic JSON text for one derived schema."""
    payload = dict(schema)
    payload["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    payload["$id"] = f"https://caudit.dev/schemas/{name}.schema.json"
    payload["x-caudit-schema-version"] = SCHEMA_VERSION
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def export_all(directory: Path | None = None) -> dict[Path, str]:
    """Render every exported schema. Returns ``{path: text}``, writing nothing."""
    target = directory or SCHEMA_DIR
    rendered = {
        target / f"{name}.schema.json": render_schema(model, name)
        for name, model in EXPORTED_MODELS.items()
    }
    rendered.update(
        {
            target / f"{name}.schema.json": render_derived(build(), name)
            for name, build in DERIVED_SCHEMAS.items()
        }
    )
    return rendered


def write_all(directory: Path | None = None) -> list[Path]:
    """Write every exported schema to disk and return the paths written."""
    written: list[Path] = []
    for path, text in export_all(directory).items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return sorted(written)


@dataclass(frozen=True)
class SchemaDrift:
    """One schema whose committed text no longer matches a fresh export."""

    path: Path
    committed: str | None
    exported: str

    def message(self) -> str:
        state = "missing" if self.committed is None else "out of date"
        return (
            f"{self.path.name} is {state}: regenerate with `make schemas` and bump "
            f"SCHEMA_VERSION (currently {SCHEMA_VERSION}) in the same change"
        )


def check_drift(directory: Path | None = None) -> list[SchemaDrift]:
    """Every committed schema that differs from a fresh export."""
    drifted: list[SchemaDrift] = []
    for path, text in export_all(directory).items():
        committed = path.read_text(encoding="utf-8") if path.is_file() else None
        if committed != text:
            drifted.append(SchemaDrift(path=path, committed=committed, exported=text))
    return sorted(drifted, key=lambda d: d.path.name)


def _walk_schema(node: object, pointer: str = "#") -> Iterator[tuple[str, Mapping[str, Any]]]:
    if isinstance(node, dict):
        yield pointer, node
        for key, value in node.items():
            yield from _walk_schema(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk_schema(value, f"{pointer}/{index}")


def structured_output_violations(schema: Mapping[str, Any]) -> list[str]:
    """Constructs in ``schema`` that a structured-output response schema rejects.

    Offline shape check only — it does not call the API. An empty list means
    part 10 can use the exported schema directly; a non-empty one means it
    needs a flattened response schema with a documented mapping.
    """
    violations: list[str] = []
    for pointer, node in _walk_schema(schema):
        for keyword in sorted(_UNSUPPORTED_KEYWORDS & set(node)):
            violations.append(f"{pointer}: unsupported keyword '{keyword}'")
    return violations
