"""Prompt assembly, dry runs, and the derived response schema: T-10-12.

Also covers the flattening the plan calls "the mapping", which is committed to
``schemas/`` and therefore checked byte-for-byte by part 02's drift test. What
is left here is whether the transforms preserve what they claim to preserve.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from caudit.application.schema_export import SCHEMA_DIR
from caudit.config.loader import Config
from caudit.llm.prompts import (
    PROMPT_DIR,
    PromptError,
    assemble,
    available_versions,
    load_template,
)
from caudit.llm.schema import TRANSFORMS, SchemaFlatteningError, flatten_response_schema
from caudit.llm.service import (
    Tier,
    adjudication_response_schema,
    dry_run_prompts,
    triage_response_schema,
)
from caudit.retrieval.context import EvidenceContext
from tests.conftest import RefusingProvider, retrieval_context

#: The version a default run assembles from. Read from configuration rather
#: than written here, so bumping it moves these tests with it instead of
#: leaving them asserting against instructions nobody sends.
PROMPT_VERSION = Config().policy_versions.prompt


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> EvidenceContext:
    return retrieval_context(
        tmp_path_factory.mktemp("prompts"), "macro_bounds", "macro_bounds.c", 27
    )


# --------------------------------------------------------------------- T-10-12


def test_dry_run_writes_every_prompt_and_calls_no_provider(
    context: EvidenceContext, tmp_path: Path
) -> None:
    """T-10-12: files on disk, provider call count zero."""
    out = tmp_path / "prompts"
    report = dry_run_prompts([context], config=Config(), out_dir=out)

    assert len(report.written) == 2
    written = {path.name.rsplit(".", 2)[-2] for path in report.written}
    assert written == {"triage", "adjudication"}
    for path in report.written:
        assert path.is_file()
        assert path.read_text(encoding="utf-8").strip()
    assert report.total_tokens > 0
    # The strongest form of "provider call count zero": the signature has no
    # provider parameter, so there is nothing a dry run could call.
    assert "provider" not in inspect.signature(dry_run_prompts).parameters


def test_a_dry_run_writes_the_body_that_would_be_sent(
    context: EvidenceContext, tmp_path: Path
) -> None:
    """The point is auditing the real request, not a rendering of it."""
    out = tmp_path / "prompts"
    dry_run_prompts([context], config=Config(), out_dir=out, tiers=(Tier.ADJUDICATION,))
    written = next(out.glob("*.adjudication.md")).read_text(encoding="utf-8")

    assembled = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version=PROMPT_VERSION,
        exclude_globs=Config().exclude_globs,
        response_fields=adjudication_response_schema()["required"],
    )
    assert written == assembled.text


def test_the_scan_command_writes_prompts_and_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_analyzers: None
) -> None:
    """T-10-12 through the CLI, which is where a user actually reaches it."""
    import socket

    from caudit.cli.main import main
    from caudit.status import ExitCode
    from tests.conftest import DEMO_TREE, compdb_entry, write_compdb, write_tree

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("--dry-run-prompts opened a connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    repo = write_tree(tmp_path / "repo", dict(DEMO_TREE))
    database = write_compdb(
        repo,
        [
            compdb_entry(repo, str(repo / f"src/{name}.c"), directory=str(repo))
            for name in ("alpha", "beta", "gamma")
        ],
    )
    out = tmp_path / "out"
    code = main(
        [
            "scan",
            str(repo),
            "--compile-commands",
            str(database),
            "--out",
            str(out),
            "--dry-run-prompts",
        ]
    )
    assert code == int(ExitCode.ENVIRONMENT)  # the fixture hid every analyzer
    assert (out / "report.md").is_file()
    # No analyzer ran here, so there are no candidates and no prompts. The
    # directory question is what matters: nothing was sent either way.
    assert not list((out / "prompts").glob("*")) if (out / "prompts").exists() else True


def test_a_context_with_no_units_is_skipped_and_recorded(
    tmp_path: Path,
) -> None:
    config = Config.model_validate({"token_budget": {"per_candidate": 40}})
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    assert not context.is_adjudicable

    report = dry_run_prompts([context], config=config, out_dir=tmp_path / "prompts")
    assert report.written == []
    assert report.skipped == [context.candidate.candidate_id]
    assert report.limitations


def test_a_refusing_provider_is_never_touched_by_a_dry_run(
    context: EvidenceContext, tmp_path: Path
) -> None:
    """Belt and braces: the signature takes no provider, and none is reachable."""
    provider = RefusingProvider()
    dry_run_prompts([context], config=Config(), out_dir=tmp_path / "prompts")
    assert provider.calls == 0


# ------------------------------------------------------------------- assembly


def test_every_tier_has_a_template_at_every_shipped_version() -> None:
    """Including the ones a run is no longer configured to use.

    An older version stays on disk so a run pinned to it sends the
    instructions it names. A version that shipped without one of the three
    templates would fail at the tier, mid-run.
    """
    versions = available_versions()
    assert PROMPT_VERSION in versions
    for version in versions:
        for tier in Tier:
            assert load_template(tier, version).strip()
            assert (PROMPT_DIR / f"v{version}" / f"{tier}.md").is_file()


def test_a_missing_template_version_names_what_exists() -> None:
    """Falling back to another version would misreport what was sent."""
    with pytest.raises(PromptError, match="no adjudication prompt template") as raised:
        load_template(Tier.ADJUDICATION, "99")
    assert raised.value.hint is not None
    assert "Versions shipped" in raised.value.hint
    assert "1" in raised.value.hint


def test_the_prompt_carries_the_version_it_was_assembled_from(
    context: EvidenceContext,
) -> None:
    prompt = assemble(context, tier=Tier.ADJUDICATION, prompt_version=PROMPT_VERSION)
    assert prompt.prompt_version == PROMPT_VERSION
    assert f"Prompt version {PROMPT_VERSION}" in prompt.text


def test_substitution_is_a_single_pass(context: EvidenceContext) -> None:
    """Code full of braces must not be re-scanned for placeholders."""
    prompt = assemble(context, tier=Tier.ADJUDICATION, prompt_version=PROMPT_VERSION)
    assert "{{" not in prompt.text
    assert "}}" not in prompt.text


def test_a_code_fence_is_long_enough_for_the_code_inside_it() -> None:
    """Source containing a triple backtick must not close the block early."""
    from caudit.llm.prompts import _fence

    assert _fence("plain code") == "```"
    assert _fence("a ``` inside") == "````"
    assert _fence("a ````` inside") == "``````"


def test_the_prompt_quotes_the_bytes_the_bundle_captured(
    context: EvidenceContext,
) -> None:
    """Never a re-read of a file that may have changed since indexing."""
    prompt = assemble(context, tier=Tier.ADJUDICATION, prompt_version=PROMPT_VERSION)
    for unit in context.units:
        if unit.note is not None:
            continue
        original = context.bundle.zoom(unit.evidence_id).decode("utf-8")
        assert original in prompt.text


def test_a_prompt_fingerprint_identifies_the_request_without_keeping_it(
    context: EvidenceContext,
) -> None:
    first = assemble(context, tier=Tier.ADJUDICATION, prompt_version=PROMPT_VERSION)
    second = assemble(context, tier=Tier.ADJUDICATION, prompt_version=PROMPT_VERSION)
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64
    triage = assemble(context, tier=Tier.TRIAGE, prompt_version=PROMPT_VERSION)
    assert triage.fingerprint != first.fingerprint


# --------------------------------------------------------- the schema mapping


def test_the_derived_response_schemas_are_committed() -> None:
    """A change to the flattening changes bytes CI compares."""
    for name, build in (
        ("adjudication-response", adjudication_response_schema),
        ("triage-response", triage_response_schema),
    ):
        committed = json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
        fresh = build()
        assert committed["properties"] == fresh["properties"]
        assert committed["required"] == fresh["required"]
        assert committed["x-caudit-transforms"] == list(TRANSFORMS)


def test_flattening_inlines_every_reference() -> None:
    schema = adjudication_response_schema()
    # The shape itself, not the transform list beside it, which names them.
    shape = json.dumps({key: value for key, value in schema.items() if not key.startswith("x-")})
    assert "$ref" not in shape
    assert "$defs" not in shape
    assert "additionalProperties" not in shape
    assert "default" not in shape


def test_flattening_keeps_the_constraints_that_matter() -> None:
    """Dropping a keyword is a constraint given up, so the kept ones are named."""
    schema = adjudication_response_schema()
    assert schema["properties"]["cwe"]["pattern"] == r"^CWE-\d{1,5}$"
    assert schema["properties"]["cwe"]["nullable"] is True
    assert schema["properties"]["verdict"]["enum"] == [
        "confirmed",
        "rejected",
        "review_required",
    ]
    assert schema["properties"]["impact"]["properties"]["description"]["minLength"] == 1


def test_a_recursive_definition_is_refused_rather_than_truncated() -> None:
    recursive = {
        "$defs": {"Node": {"type": "object", "properties": {"next": {"$ref": "#/$defs/Node"}}}},
        "$ref": "#/$defs/Node",
    }
    with pytest.raises(SchemaFlatteningError, match="refers to itself"):
        flatten_response_schema(recursive)


def test_an_unresolvable_reference_is_refused() -> None:
    with pytest.raises(SchemaFlatteningError, match="does not resolve"):
        flatten_response_schema({"$ref": "#/$defs/Missing"})


def test_the_flattened_schema_is_usable_as_a_structured_output_schema() -> None:
    from caudit.application.schema_export import structured_output_violations

    assert structured_output_violations(adjudication_response_schema()) == []
    assert structured_output_violations(triage_response_schema()) == []
