"""Part 01 secret-safety tests: T-01-09, T-01-10.

AC-01-6 is absolute — *no* log record, at any level, may contain the value of
GEMINI_API_KEY — so these tests go looking for it rather than sampling.
"""

from __future__ import annotations

import io
import logging

import pytest

from caudit.cli.main import main
from caudit.logging import REDACTED, configure_logging, get_logger, redact

SECRET = "sk-secret123456789"
GOOGLE_SHAPED = "AIzaSyD-1234567890abcdefghijklmnopqrstu"


def test_api_key_never_reaches_a_log_record_or_the_config_dump(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-01-09: DEBUG logging plus --print-config, with the key in the env."""
    monkeypatch.setenv("GEMINI_API_KEY", SECRET)
    stream = io.StringIO()
    configure_logging(logging.DEBUG, stream=stream)
    log = get_logger("test")

    # Every level, and every way a value can enter a record.
    log.debug("key is %s", SECRET)
    log.info("inline %s here", SECRET)
    log.warning(f"f-string {SECRET}")
    log.error("dict %s", {"api_key": SECRET})
    try:
        raise RuntimeError(f"boom {SECRET}")
    except RuntimeError:
        log.exception("failed")

    logged = stream.getvalue()
    assert SECRET not in logged
    assert REDACTED in logged

    code = main(["--print-config"])
    captured = capsys.readouterr()
    assert code == 0
    assert SECRET not in captured.out
    assert SECRET not in captured.err
    # The key is not a configuration field at all, so it cannot be dumped.
    assert "GEMINI_API_KEY" in captured.out  # only as an explanatory note


def test_records_themselves_are_scrubbed_not_just_the_formatted_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A handler that formats records its own way must still be safe."""
    monkeypatch.setenv("GEMINI_API_KEY", SECRET)
    configure_logging(logging.DEBUG, stream=io.StringIO())

    captured: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    handler = Capture()
    from caudit.logging import RedactingFilter

    handler.addFilter(RedactingFilter())
    logger = get_logger("record-test")
    logger.addHandler(handler)
    logger.error("token %s", SECRET)

    assert captured
    for record in captured:
        assert SECRET not in record.getMessage()
        assert SECRET not in str(record.msg)
        assert SECRET not in str(record.args)


def test_google_shaped_token_is_redacted_without_registration() -> None:
    """T-01-10: an inline AIza…-shaped token is replaced by the formatter."""
    stream = io.StringIO()
    configure_logging(logging.DEBUG, stream=stream, env={})
    get_logger("shape").info("using %s for the call", GOOGLE_SHAPED)
    logged = stream.getvalue()
    assert GOOGLE_SHAPED not in logged
    assert REDACTED in logged


@pytest.mark.parametrize(
    "text",
    [
        "api_key=abcdef123456",
        'API-KEY: "hunter2hunter2"',
        "password = correcthorsebattery",
        "authorization token: ya29.averylongtokenvalue123",
        "sk-abcdefghijklmnop",
    ],
)
def test_common_secret_shapes_are_redacted(text: str) -> None:
    assert REDACTED in redact(text)


def test_short_values_are_not_registered_as_secrets() -> None:
    """Redacting a two-character string would corrupt unrelated output."""
    from caudit.logging import register_secret, registered_secrets

    register_secret("ab")
    assert "ab" not in registered_secrets()
    assert redact("a table of abbreviations") == "a table of abbreviations"
