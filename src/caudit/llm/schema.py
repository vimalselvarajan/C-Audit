"""The response schema a provider is actually given, and how it was derived.

The model's output is constrained by the same pydantic definitions that
validate it, so there is no second description of a finding that can drift
from the first. What a provider will *accept* as a response schema is narrower
than JSON Schema, though, so the exported schema is put through a small,
explicit set of transforms here.

Every transform is listed in :data:`TRANSFORMS`, applied by exactly one
function, and the result is committed to ``schemas/`` — which is what turns
"the mapping is documented" into a check CI runs. A transform that started
dropping a constraint would change the committed bytes, and the drift check
fails before anything is sent anywhere.

Nothing in here is provider-specific beyond the constructs it removes. A
backend that accepts full JSON Schema can use
:func:`caudit.application.schema_export.render_schema` directly; this is the lowest
common denominator, not a Gemini dialect.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from pydantic import BaseModel

from caudit.model.adjudication import Adjudication, TriageResult

__all__ = [
    "TRANSFORMS",
    "adjudication_response_schema",
    "flatten_response_schema",
    "triage_response_schema",
]

#: Keywords removed outright. Each one is either unsupported by structured
#: output or meaningless in a response schema, and each removal is a
#: constraint given up — so the list is short and the reason is stated.
_DROPPED: Final[Mapping[str, str]] = {
    # Bookkeeping about the schema document, not about the response.
    "$schema": "identifies the JSON Schema dialect; not part of the shape",
    "$id": "identifies this document; not part of the shape",
    "x-caudit-schema-version": "our own annotation, carried in the cache key instead",
    "$defs": "inlined at every reference, so no definition block survives",
    # Not accepted in a response schema.
    "additionalProperties": "rejected by structured output; unknown keys are refused "
    "by the pydantic model instead, which is the check that matters",
    "default": "a response schema describes what must be returned, not what to "
    "assume when it is not",
    "title": "pydantic derives it from the class name; it is noise in a prompt",
    "discriminator": "rejected by structured output; the union it tags is inlined",
}

#: Human-readable description of what :func:`flatten_response_schema` does,
#: rendered into the committed schema's ``x-caudit-transforms`` field so the
#: mapping travels with the artifact it produced.
TRANSFORMS: Final[tuple[str, ...]] = (
    "$ref/$defs are inlined at every use; a recursive definition is refused",
    *(f"'{keyword}' is removed: {reason}" for keyword, reason in sorted(_DROPPED.items())),
    "anyOf with exactly one non-null branch becomes that branch plus nullable=true",
    "properties are emitted in the order the model declares them",
)


class SchemaFlatteningError(ValueError):
    """A schema this module refuses to flatten rather than flatten wrongly."""


def flatten_response_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Inline every reference and drop every construct a response schema refuses.

    Recursion is refused rather than truncated: a model type that refers to
    itself has no finite inlined form, and silently cutting the cycle would
    hand a provider a schema that accepts less than the validator does.
    """
    definitions = schema.get("$defs", {})
    if not isinstance(definitions, dict):  # pragma: no cover - pydantic always emits a dict
        definitions = {}
    rewritten = _rewrite(schema, definitions, ())
    if not isinstance(rewritten, dict):  # pragma: no cover - a schema is always an object
        raise SchemaFlatteningError("the top level of a response schema must be an object")
    return rewritten


def _rewrite(
    node: Any,
    definitions: Mapping[str, Any],
    stack: tuple[str, ...],
) -> Any:
    if isinstance(node, list):
        return [_rewrite(item, definitions, stack) for item in node]
    if not isinstance(node, dict):
        return node

    reference = node.get("$ref")
    if isinstance(reference, str):
        name = reference.rsplit("/", 1)[-1]
        if name in stack:
            raise SchemaFlatteningError(
                f"'{name}' refers to itself; a recursive definition cannot be inlined "
                "into a response schema"
            )
        target = definitions.get(name)
        if target is None:
            raise SchemaFlatteningError(f"'{reference}' does not resolve to a definition")
        # Sibling keywords beside a $ref (pydantic emits `description`) survive
        # the inlining and win, which is how a field's own prose keeps priority
        # over the shared definition's.
        inlined = _rewrite(target, definitions, (*stack, name))
        siblings = {key: value for key, value in node.items() if key != "$ref"}
        inlined.update(_rewrite(siblings, definitions, stack))
        return inlined

    rewritten: dict[str, Any] = {}
    for key, value in node.items():
        if key in _DROPPED:
            continue
        rewritten[key] = _rewrite(value, definitions, stack)

    return _collapse_nullable(rewritten)


def _collapse_nullable(node: dict[str, Any]) -> dict[str, Any]:
    """``anyOf: [X, null]`` becomes ``X`` with ``nullable: true``."""
    branches = node.get("anyOf")
    if not isinstance(branches, Sequence) or isinstance(branches, str | bytes):
        return node
    concrete = [branch for branch in branches if branch != {"type": "null"}]
    if len(concrete) != 1 or len(concrete) == len(branches):
        return node
    only = concrete[0]
    if not isinstance(only, dict):  # pragma: no cover - pydantic emits objects
        return node
    merged = {key: value for key, value in node.items() if key != "anyOf"}
    # The branch supplies the shape; the field's own keywords stay on top.
    collapsed = dict(only)
    collapsed.update(merged)
    collapsed["nullable"] = True
    return collapsed


def _response_schema(model: type[BaseModel], name: str) -> dict[str, Any]:
    flattened = flatten_response_schema(model.model_json_schema(mode="serialization"))
    flattened["x-caudit-response-schema"] = name
    flattened["x-caudit-transforms"] = list(TRANSFORMS)
    return flattened


def adjudication_response_schema() -> dict[str, Any]:
    """What the adjudication and escalation tiers must return."""
    return _response_schema(Adjudication, "adjudication")


def triage_response_schema() -> dict[str, Any]:
    """What the triage tier must return."""
    return _response_schema(TriageResult, "triage")
