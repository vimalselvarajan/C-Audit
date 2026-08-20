"""Consent, exclusion, redaction, and key hygiene: T-10-08..T-10-11.

Every test here is written to fail loudly rather than quietly. A socket that
should not open raises on connect instead of being counted afterwards; a
provider that should not be called raises when called; a file that must not be
transmitted carries a marker string that appears nowhere else in the tree, so a
leak is a substring search rather than an inference.
"""

from __future__ import annotations

import io
import json
import logging
import socket
from pathlib import Path

import pytest

from caudit.cli.main import main
from caudit.config.loader import Config
from caudit.llm.consent import CONSENT_RELATIVE_PATH, ConsentError
from caudit.llm.prompts import assemble
from caudit.llm.redaction import RedactionKind, mask_excluded_paths, scrub
from caudit.llm.service import (
    ConsentSource,
    PrivacyError,
    RunAccount,
    Tier,
    adjudicate,
    consent_state,
    record_consent,
    require_consent,
    response_cache,
)
from caudit.logging import configure_logging, register_secret
from caudit.retrieval.context import EvidenceContext
from caudit.status import ExitCode
from tests.conftest import (
    DEMO_TREE,
    RefusingProvider,
    cassette_provider,
    compdb_entry,
    granted_consent,
    no_sleep,
    retrieval_context,
    write_compdb,
    write_tree,
)

#: A string that exists nowhere in this repository except the excluded fixture
#: header. Its absence from a prompt is a fact, not an interpretation.
EXCLUDED_MARKER = "ZZTOP-THIS-STRING-MUST-NEVER-BE-TRANSMITTED"

SECRETS_CONFIG = {"exclude_globs": ["secrets/**"]}


@pytest.fixture
def excluded_config() -> Config:
    return Config.model_validate(SECRETS_CONFIG)


# --------------------------------------------------------------------- T-10-08


class _LoudSocket(socket.socket):
    """A socket that refuses to be opened, with a message that names the test."""

    def __init__(self, *args: object, **kwargs: object) -> None:  # pragma: no cover - never runs
        raise AssertionError("a socket was opened during a run that had no cloud consent")


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to reach the network fails immediately and loudly."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a network connection was attempted")

    monkeypatch.setattr(socket, "socket", _LoudSocket)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def test_a_scan_without_consent_opens_no_socket_and_still_writes_the_report(
    tmp_path: Path, no_network: None, no_analyzers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-10-08: no consent, no connections, and the baseline report is still there."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    repo = write_tree(tmp_path / "repo", dict(DEMO_TREE))
    write_compdb(
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
            str(repo / "build" / "compile_commands.json"),
            "--out",
            str(out),
        ]
    )

    # 3, not 0: the fixture hid every analyzer, so nothing was examined. The
    # point of the test is that the run completed and wrote its artifacts.
    assert code == int(ExitCode.ENVIRONMENT)
    assert (out / "report.md").is_file()
    assert (out / "results.sarif").is_file()
    assert (out / "run-manifest.json").is_file()

    manifest = json.loads((out / "run-manifest.json").read_text(encoding="utf-8"))
    # Empty is the claim: no tier was consulted.
    assert manifest["models"] == []
    assert manifest["config_snapshot"]["cloud_consent"] is False

    report = (out / "report.md").read_text(encoding="utf-8")
    assert "cloud consent was not given" in report


def test_the_absence_of_consent_is_recorded_rather_than_implied() -> None:
    decision = consent_state(Config())
    assert not decision.granted
    assert decision.source is ConsentSource.ABSENT
    limitation = decision.as_limitation()
    assert "--consent-cloud" in limitation.detail


def test_nothing_can_be_adjudicated_without_consent(tmp_path: Path) -> None:
    """The gate is a call every path makes, not a flag each path reads."""
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27)
    config = Config()
    with pytest.raises(ConsentError, match="explicit consent"):
        adjudicate(
            context,
            config=config,
            provider=RefusingProvider(),
            consent=consent_state(config),
            account=RunAccount(config=config),
            sleeper=no_sleep,
        )


def test_the_gemini_backend_cannot_be_constructed_without_consent() -> None:
    """The only component that can open a socket takes consent as an argument."""
    from caudit.llm.gemini import GeminiProvider

    with pytest.raises(ConsentError):
        GeminiProvider(consent=consent_state(Config()))


def test_the_consent_flag_can_only_grant_never_withdraw() -> None:
    """An omitted flag must not overwrite a consent given in configuration."""
    from caudit.cli.scan_cmd import apply_scan_overrides

    consented = Config.model_validate({"cloud_consent": True})
    kept = apply_scan_overrides(consented, targets=[], allow_partial_coverage=False)
    assert kept.cloud_consent is True

    withheld = apply_scan_overrides(Config(), targets=[], allow_partial_coverage=False)
    assert withheld.cloud_consent is False


def test_a_persisted_record_grants_consent_and_deleting_it_withdraws(
    tmp_path: Path,
) -> None:
    assert not consent_state(Config(), tmp_path).granted
    written = record_consent(tmp_path, caudit_version="0.1.0")
    assert written == tmp_path / CONSENT_RELATIVE_PATH

    decision = consent_state(Config(), tmp_path)
    assert decision.granted
    assert decision.source is ConsentSource.RECORD

    written.unlink()
    assert not consent_state(Config(), tmp_path).granted


def test_a_malformed_or_negative_record_is_not_an_affirmation(tmp_path: Path) -> None:
    path = tmp_path / CONSENT_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    for content in ("not json at all", '{"granted": false}', '{"granted": "yes"}', "[]"):
        path.write_text(content, encoding="utf-8")
        assert not consent_state(Config(), tmp_path).granted


# --------------------------------------------------------------------- T-10-09


def _secrets_context(tmp_path: Path, line: int, config: Config) -> EvidenceContext:
    return retrieval_context(tmp_path, "secrets", "src/session.c", line, config=config)


def test_no_byte_of_an_excluded_file_reaches_an_assembled_prompt(
    tmp_path: Path, excluded_config: Config
) -> None:
    """T-10-09: the macro is retrieved, and it is withheld."""
    context = _secrets_context(tmp_path, 44, excluded_config)
    # Part 09 did its job: the definition is in the context.
    withheld = [unit for unit in context.units if "secrets/" in str(unit.region.path)]
    assert withheld, "the fixture no longer exercises the exclusion path"

    prompt = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version="1",
        exclude_globs=excluded_config.exclude_globs,
    )
    assert EXCLUDED_MARKER not in prompt.text
    assert "PRIVATE KEY" not in prompt.text
    assert "secrets/keys.h" not in prompt.text
    for unit in withheld:
        assert unit.evidence_id not in prompt.evidence_ids


def test_the_model_is_told_that_something_was_withheld_without_being_told_what(
    tmp_path: Path, excluded_config: Config
) -> None:
    """A missing definition read as an absent one is the failure part 09 prevents."""
    context = _secrets_context(tmp_path, 44, excluded_config)
    prompt = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version="1",
        exclude_globs=excluded_config.exclude_globs,
    )
    assert "[caudit:withheld:excluded-file]" in prompt.text
    assert "withheld from the model" in prompt.text
    # The report still learns the path; only the prompt does not.
    assert any("secrets/keys.h" in item.detail for item in prompt.limitations)


def test_the_exclusion_assertion_actually_fires(excluded_config: Config) -> None:
    """A check that cannot fail proves nothing about the one that must not."""
    from caudit.evidence.filters import PathFilter
    from caudit.llm.redaction import assert_nothing_excluded

    path_filter = PathFilter(excluded_config.exclude_globs)
    with pytest.raises(PrivacyError, match="reached the assembled prompt"):
        assert_nothing_excluded(
            paths=["secrets/keys.c"], generated_text="", path_filter=path_filter
        )
    with pytest.raises(PrivacyError, match="names excluded file"):
        assert_nothing_excluded(
            paths=[],
            generated_text="see secrets/keys.h for the definition",
            path_filter=path_filter,
        )


def test_quoted_code_keeps_its_own_include_lines(tmp_path: Path, excluded_config: Config) -> None:
    """Masking applies to prose we wrote, never to a file's own bytes."""
    from caudit.evidence.filters import PathFilter

    path_filter = PathFilter(excluded_config.exclude_globs)
    masked, count = mask_excluded_paths("withheld: secrets/keys.h", path_filter)
    assert count == 1
    assert "secrets/keys.h" not in masked

    untouched, none = mask_excluded_paths("src/session.c is fine", path_filter)
    assert none == 0
    assert untouched == "src/session.c is fine"


# --------------------------------------------------------------------- T-10-10


def test_credential_shapes_are_redacted_and_counted(
    tmp_path: Path, excluded_config: Config
) -> None:
    """T-10-10: an AWS key id in the primary unit, and the count is recorded."""
    context = _secrets_context(tmp_path, 37, excluded_config)
    prompt = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version="1",
        exclude_globs=excluded_config.exclude_globs,
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in prompt.text
    assert "hunter2-not-a-real-password" not in prompt.text
    assert prompt.redactions.count >= 2
    assert str(RedactionKind.AWS_ACCESS_KEY) in prompt.redactions.by_kind
    assert str(RedactionKind.ASSIGNED_LITERAL) in prompt.redactions.by_kind
    assert "[caudit:redacted:aws_access_key]" in prompt.text


def test_a_redacted_primary_unit_becomes_a_limitation(
    tmp_path: Path, excluded_config: Config
) -> None:
    """The model read text that differs from the code, and the report says so."""
    context = _secrets_context(tmp_path, 37, excluded_config)
    prompt = assemble(
        context,
        tier=Tier.ADJUDICATION,
        prompt_version="1",
        exclude_globs=excluded_config.exclude_globs,
    )
    details = [item.detail for item in prompt.limitations]
    assert any("redacted quotation" in detail for detail in details)
    assert any("session_open" in detail for detail in details)


def test_a_pem_block_is_redacted_whole() -> None:
    text = (
        "static const char key[] =\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAsecretbytes\n"
        "-----END RSA PRIVATE KEY-----\n"
        ";\n"
    )
    scrubbed, report = scrub(text)
    assert "MIIEowIBAAKCAQEA" not in scrubbed
    assert report.by_kind == {str(RedactionKind.PRIVATE_KEY_BLOCK): 1}


def test_redaction_never_rewrites_an_expression() -> None:
    """A rule broad enough to catch `secret = compute(x)` would delete code."""
    code = "int secret = compute(x, y);\nchar *token = lexer_next(state);\n"
    scrubbed, report = scrub(code)
    assert scrubbed == code
    assert report.clean


def test_one_secret_is_counted_once() -> None:
    """Two rules matching the same span is one redaction, not two."""
    _text, report = scrub('const char *api_key = "AIzaSyD0000000000000000000000000";')
    assert report.count == 1


# --------------------------------------------------------------------- T-10-11


def test_the_api_key_reaches_no_prompt_log_cache_or_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-10-11: one distinctive key value, and a search of everything written."""
    key = "AIzaSyCAUDITTESTKEY0000000000000000000000"
    monkeypatch.setenv("GEMINI_API_KEY", key)
    register_secret(key)

    stream = io.StringIO()
    configure_logging(logging.DEBUG, stream=stream, env={"GEMINI_API_KEY": key})

    config = Config.model_validate(
        {
            "llm": {
                "triage_enabled": False,
                "cache_enabled": True,
                "cache_dir": str(tmp_path / "cache"),
                "retain_raw": True,
            }
        }
    )
    context = retrieval_context(tmp_path, "macro_bounds", "macro_bounds.c", 27, config=config)
    provider, _ = cassette_provider("adjudication-confirmed", evidence_ids=context.evidence_ids())
    account = RunAccount(config=config)
    outcome = adjudicate(
        context,
        config=config,
        provider=provider,
        consent=granted_consent(),
        account=account,
        cache=response_cache(config),
        sleeper=no_sleep,
    )
    assert outcome.accepted

    logging.getLogger("caudit.test").error("the key is %s", key)

    # The prompt actually sent.
    assert key not in provider.requests[0].body()
    # Every cache file, including the retained raw exchange.
    for path in (tmp_path / "cache").rglob("*"):
        if path.is_file():
            assert key not in path.read_text(encoding="utf-8")
    # The log.
    assert key not in stream.getvalue()
    assert "***redacted***" in stream.getvalue()
    # The configuration snapshot a manifest carries.
    assert key not in json.dumps(config.model_dump(mode="json"))
    # And the outcome itself, which is what part 11 receives.
    assert key not in outcome.model_dump_json()


def test_the_key_is_not_a_configuration_field() -> None:
    """It cannot be dumped by --print-config because it is not config."""
    from caudit.config.loader import config_key_paths

    keys = " ".join(config_key_paths()).lower()
    assert "api_key" not in keys
    assert "gemini_api_key" not in keys


def test_a_key_in_the_source_itself_is_scrubbed_before_assembly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A registered secret is replaced wherever it appears, source included."""
    key = "AIzaSyCAUDITINSOURCE000000000000000000000"
    register_secret(key)
    scrubbed, report = scrub(f'const char *k = "{key}";')
    assert key not in scrubbed
    assert report.count == 1
    assert str(RedactionKind.REGISTERED_SECRET) in report.by_kind


def test_require_consent_is_a_no_op_when_it_is_granted() -> None:
    require_consent(granted_consent())
