"""Versioned prompt assembly.

Templates are files, not string literals, and they are versioned by directory.
That is not tidiness: the prompt version is part of the cache key and is
recorded in the run manifest, so a report can name the instructions that
produced it, and a cassette recorded against ``v1`` cannot silently be replayed
against ``v2``.

Assembly is the last place a decision about *what leaves the process* is made,
so the order here is load-bearing:

1. units whose file is excluded are removed, and each removal becomes a
   limitation — the exclusion is enforced before anything is rendered;
2. each unit's exact bytes are taken from the bundle, never re-read from disk,
   so the prompt quotes the revision that was indexed;
3. every rendered body is scrubbed, and a redaction inside a primary unit
   becomes a limitation of its own;
4. the assembled text is checked against the exclusion filter a second time.

Substitution is a single regex pass over ``{{NAME}}`` placeholders. One pass
matters: source code is full of braces, and a second pass over already
substituted text could find a placeholder that came out of the repository.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from caudit.errors import CauditError
from caudit.evidence.filters import PathFilter
from caudit.llm.redaction import (
    RedactionReport,
    assert_nothing_excluded,
    excluded_limitation,
    mask_excluded_paths,
    partition_excluded,
    redaction_limitations,
    scrub,
)
from caudit.model.adjudication import Tier
from caudit.model.finding import Limitation
from caudit.retrieval.budget import DEFAULT_TOKENIZER, Tokenizer
from caudit.retrieval.context import ContextUnit, EvidenceContext

__all__ = [
    "PROMPT_DIR",
    "AssembledPrompt",
    "PromptError",
    "assemble",
    "available_versions",
    "load_template",
]

PROMPT_DIR: Final = Path(__file__).resolve().parent

_PLACEHOLDER: Final = re.compile(r"\{\{([A-Z_]+)\}\}")
_FENCE_RUN: Final = re.compile(r"`+")


class PromptError(CauditError):
    """A prompt cannot be assembled as described."""


def available_versions() -> tuple[str, ...]:
    """Prompt versions shipped with this package, newest last."""
    return tuple(
        sorted(
            path.name.removeprefix("v")
            for path in PROMPT_DIR.iterdir()
            if path.is_dir() and path.name.startswith("v")
        )
    )


@lru_cache(maxsize=32)
def load_template(tier: Tier, version: str) -> str:
    """One tier's template text, by version.

    A missing template is an error naming what exists. Falling back to another
    version would put a run's recorded prompt version at odds with the
    instructions it actually sent.
    """
    path = PROMPT_DIR / f"v{version}" / f"{tier}.md"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PromptError(
            f"no {tier} prompt template at version {version}",
            hint=f"Versions shipped with this build: {', '.join(available_versions()) or 'none'}.",
        ) from exc


class AssembledPrompt(BaseModel):
    """One request body, and everything a run needs to record about it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: Tier
    prompt_version: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    #: Exactly what the model may cite. An id outside this tuple is rejected
    #: before any file is opened.
    evidence_ids: tuple[str, ...] = ()
    redactions: RedactionReport = Field(default_factory=RedactionReport)
    token_estimate: int = Field(default=0, ge=0)
    #: Units withheld, and primaries whose text was rewritten.
    limitations: list[Limitation] = Field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Content address of the request body.

        Recorded instead of the prompt itself: it identifies the request for
        cache lookups and cross-run comparison without persisting source.
        """
        return sha256(self.text.encode("utf-8")).hexdigest()


def assemble(
    context: EvidenceContext,
    *,
    tier: Tier,
    prompt_version: str,
    exclude_globs: Sequence[str] = (),
    tokenizer: Tokenizer = DEFAULT_TOKENIZER,
    response_fields: Sequence[str] = (),
) -> AssembledPrompt:
    """Render one candidate's context into a request body."""
    path_filter = PathFilter(exclude_globs)
    sendable, excluded = partition_excluded(context.units, path_filter)
    limitations = [excluded_limitation(unit, path_filter) for unit in excluded]

    bodies: list[str] = []
    reports: list[RedactionReport] = []
    for unit in sendable:
        body, report = scrub(_unit_body(context, unit))
        bodies.append(_render_unit(unit, body))
        reports.append(report)
    limitations.extend(redaction_limitations(sendable, reports))

    # Prose this package writes is masked; quoted code is not. A path inside a
    # non-excluded file's source is that file's content, and rewriting it to
    # satisfy a rule about prose would be editing code.
    generated = {
        "CANDIDATE": _render_candidate(context),
        "EVIDENCE_IDS": _render_evidence_ids(sendable),
        "LIMITATIONS": _render_limitations([*context.limitations, *limitations]),
    }
    masked = {key: mask_excluded_paths(value, path_filter)[0] for key, value in generated.items()}
    assert_nothing_excluded(
        paths=[*(unit.region.path for unit in sendable), context.candidate.region.path],
        generated_text="\n".join(masked.values()),
        path_filter=path_filter,
    )

    text = _substitute(
        load_template(tier, prompt_version),
        {
            "TIER": str(tier),
            "PROMPT_VERSION": prompt_version,
            "CONTEXT": "\n\n".join(bodies) if bodies else "_No code could be retrieved._",
            "RESPONSE_FIELDS": ", ".join(response_fields) or "the response schema's fields",
            **masked,
        },
    )
    # The scaffolding has not been through a scrubber yet. The unit bodies
    # have, and a placeholder matches nothing, so nothing is counted twice.
    text, tail = scrub(text)
    total = RedactionReport()
    for report in [*reports, tail]:
        total = total.merged_with(report)

    return AssembledPrompt(
        tier=tier,
        prompt_version=prompt_version,
        candidate_id=context.candidate.candidate_id,
        text=text,
        evidence_ids=tuple(unit.evidence_id for unit in sendable),
        redactions=total,
        token_estimate=tokenizer.count(text),
        limitations=limitations,
    )


# ---------------------------------------------------------------- rendering


def _substitute(template: str, values: Mapping[str, str]) -> str:
    """One pass, so substituted text is never re-scanned for placeholders."""
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            missing.append(name)
            return match.group(0)
        return values[name]

    rendered = _PLACEHOLDER.sub(replace, template)
    if missing:
        raise PromptError(
            f"the template asks for {', '.join(sorted(set(missing)))}, which assembly "
            "does not supply"
        )
    return rendered


def _unit_body(context: EvidenceContext, unit: ContextUnit) -> str:
    """The unit's own text: an analyzer's prose, or the exact captured bytes."""
    if unit.note is not None:
        return unit.note
    return _decode(context.bundle.zoom(unit.evidence_id))


def _decode(data: bytes) -> str:
    """Bytes to text for display, never silently lossy about what was there."""
    return data.decode("utf-8", errors="replace")


def _fence(text: str) -> str:
    """A fence longer than any backtick run inside ``text``.

    Source containing a triple backtick — a doc comment, a string literal —
    would otherwise close the block early and hand the model code that reads as
    instructions.
    """
    longest = max((len(run) for run in _FENCE_RUN.findall(text)), default=0)
    return "`" * max(3, longest + 1)


def _render_unit(unit: ContextUnit, body: str) -> str:
    symbol = f" — `{unit.symbol.name}`" if unit.symbol else ""
    repeats = f", reported {unit.occurrences} times" if unit.is_compressed else ""
    fence = _fence(body)
    language = "" if unit.note is not None else "c"
    return (
        f"### {unit.role}{symbol}\n"
        f"- evidence id: `{unit.evidence_id}`\n"
        f"- location: `{unit.region.describe()}`{repeats}\n\n"
        f"{fence}{language}\n{body}\n{fence}"
    )


def _render_candidate(context: EvidenceContext) -> str:
    candidate = context.candidate
    tools = ", ".join(
        f"{entry.tool_name} {entry.tool_version}" + (f" [{entry.rule_id}]" if entry.rule_id else "")
        for entry in candidate.provenance
    )
    suggested = ", ".join(candidate.suggested_cwe) or "none"
    return (
        f"- location: `{candidate.region.describe()}`\n"
        f"- analyzer message: {candidate.message}\n"
        f"- reported by: {tools}\n"
        f"- CWEs the analyzer suggested: {suggested}\n"
        f"- retrieval: {context.describe()}"
    )


def _render_evidence_ids(units: Sequence[ContextUnit]) -> str:
    if not units:
        return "_None. With nothing citable, no verdict but `review_required` is available._"
    return "\n".join(f"- `{unit.evidence_id}` — {unit.describe()}" for unit in units)


def _render_limitations(limitations: Sequence[Limitation]) -> str:
    if not limitations:
        return "_None recorded._"
    seen: list[str] = []
    for limitation in limitations:
        line = f"- [{limitation.kind}] {limitation.detail}"
        if line not in seen:
            seen.append(line)
    return "\n".join(seen)


def prompt_paths(out_dir: Path, candidate_id: str, tier: Tier) -> Path:
    """Where ``--dry-run-prompts`` writes one assembled prompt."""
    return out_dir / f"{_safe(candidate_id)}.{tier}.md"


def _safe(candidate_id: str) -> str:
    """A candidate id reduced to something a filesystem accepts."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", candidate_id) or "candidate"
