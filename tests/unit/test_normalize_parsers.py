"""Part 07 parser tests: T-07-07, T-07-08, T-07-09, T-07-10, T-07-17.

Each analyzer's native format is parsed here, before anything is normalized.
Keeping the two apart matters: a wrong note-to-parent attachment and a wrong
region hash are different bugs, and a test that only looked at the finished
candidate would not say which one it caught.
"""

from __future__ import annotations

from pathlib import Path

from caudit.analyzers.csa import parse_sarif
from caudit.analyzers.diagnostics import parse_json_diagnostics, parse_text_diagnostics
from caudit.analyzers.normalize import DiagnosticSeverity
from caudit.analyzers.profile import load_profile
from caudit.analyzers.tidy import parse_export_fixes
from caudit.model.evidence import EvidenceKind, Producer
from tests.conftest import analyzer_fixture


def _read(*parts: str) -> str:
    return analyzer_fixture(*parts).read_text(encoding="utf-8")


# ------------------------------------------------------------------ CSA


def test_csa_code_flow_becomes_four_ordered_control_flow_steps() -> None:
    """T-07-07: the analyzer's path is the argument, so its order is evidence."""
    parsed = parse_sarif(_read("csa", "four-step-flow.sarif"), tool_version="18.1.8")

    assert len(parsed) == 1
    diagnostic = parsed[0]
    assert diagnostic.producer is Producer.CSA
    assert diagnostic.rule_id == "unix.Malloc"
    assert diagnostic.line == 5

    assert [step.line for step in diagnostic.flow] == [1, 3, 4, 5]
    assert all(step.kind is EvidenceKind.CONTROL_FLOW_STEP for step in diagnostic.flow)
    assert diagnostic.flow[0].message == "Memory is allocated"
    assert diagnostic.flow[-1].message == "Use of memory after it is freed"


def test_csa_result_without_a_rule_id_falls_back_to_the_rule_index() -> None:
    document = _read("csa", "four-step-flow.sarif").replace('"ruleId": "unix.Malloc",', "")
    parsed = parse_sarif(document, tool_version="18.1.8")
    assert [item.rule_id for item in parsed] == ["unix.Malloc"]


def test_csa_parser_survives_output_that_is_not_sarif() -> None:
    """A crashed analyzer's truncated file must not raise over its own failure."""
    assert parse_sarif("", tool_version="18") == []
    assert parse_sarif("{ not json", tool_version="18") == []
    assert parse_sarif('{"runs": [{"results": [{}]}]}', tool_version="18") == []


def test_csa_file_uri_scheme_is_stripped() -> None:
    document = _read("csa", "four-step-flow.sarif").replace(
        '"src/main.c"', '"file:///w/src/main.c"'
    )
    parsed = parse_sarif(document, tool_version="18.1.8")
    assert parsed[0].path == "/w/src/main.c"


# ------------------------------------------------------------- clang-tidy


def test_tidy_notes_attach_to_their_parent_diagnostic() -> None:
    """T-07-08: two notes, one diagnostic — never three diagnostics."""
    parsed = parse_export_fixes(_read("tidy", "notes-and-fix.yaml"), tool_version="18.1.8")

    assert len(parsed) == 1
    diagnostic = parsed[0]
    assert diagnostic.producer is Producer.CLANG_TIDY
    assert diagnostic.rule_id == "clang-analyzer-security.insecureAPI.strcpy"
    assert len(diagnostic.notes) == 2
    assert diagnostic.notes[0].message == "destination buffer declared here"


def test_tidy_suggested_fix_is_recorded_as_text(tmp_path: Path) -> None:
    """T-07-09: the fix is provenance, not an edit. Nothing is written."""
    before = sorted(path.name for path in tmp_path.iterdir())
    parsed = parse_export_fixes(_read("tidy", "notes-and-fix.yaml"), tool_version="18.1.8")

    assert parsed[0].fix is not None
    assert "strlcpy" in parsed[0].fix
    assert sorted(path.name for path in tmp_path.iterdir()) == before


def test_tidy_parser_survives_output_that_is_not_a_fixes_document() -> None:
    assert parse_export_fixes("", tool_version="18") == []
    assert parse_export_fixes("[1, 2", tool_version="18") == []
    assert parse_export_fixes("Diagnostics:\n  - {}\n", tool_version="18") == []


# ------------------------------------------------------------ diagnostics


def test_json_diagnostics_keep_their_severities() -> None:
    """T-07-10: a warning and an error, each parsed as what it said it was."""
    parsed = parse_json_diagnostics(
        _read("diagnostics", "warning-and-error.json"), tool_version="18.1.8"
    )

    severities = {item.rule_id: item.severity for item in parsed}
    assert severities == {
        "-Wformat-security": DiagnosticSeverity.WARNING,
        "-Wimplicit-function-declaration": DiagnosticSeverity.ERROR,
    }
    assert all(item.producer is Producer.CLANG_DIAGNOSTIC for item in parsed)


def test_json_notes_attach_to_their_parent_and_a_bare_note_is_dropped() -> None:
    parsed = parse_json_diagnostics(
        _read("diagnostics", "warning-and-error.json"), tool_version="18.1.8"
    )
    warning = next(item for item in parsed if item.rule_id == "-Wformat-security")

    assert [note.message for note in warning.notes] == [
        "treat the string as an argument to avoid this"
    ]
    assert warning.fix is not None and "%s" in warning.fix
    # The third entry in the fixture is a note with no parent.
    assert len(parsed) == 2


def test_text_diagnostics_keep_their_severities_and_attach_notes() -> None:
    """The default format: Clang has no JSON diagnostics, so text must work."""
    parsed = parse_text_diagnostics(
        _read("diagnostics", "warning-and-error.txt"), tool_version="18.1.8"
    )

    by_rule = {item.rule_id: item for item in parsed}
    assert by_rule["-Wformat-security"].severity is DiagnosticSeverity.WARNING
    assert by_rule["-Wimplicit-function-declaration"].severity is DiagnosticSeverity.ERROR
    assert [note.message for note in by_rule["-Wformat-security"].notes] == [
        "treat the string as an argument to avoid this"
    ]
    # The system-header warning is parsed here and dropped at normalization,
    # which is where "outside the repository" is decided.
    assert any(item.path.startswith("/usr/include") for item in parsed)


def test_a_note_before_any_diagnostic_is_dropped_rather_than_promoted() -> None:
    text = "src/a.c:1:1: note: orphan\nsrc/a.c:2:1: warning: real [-Wshadow]\n"
    parsed = parse_text_diagnostics(text, tool_version="18")
    assert [item.message for item in parsed] == ["real"]
    assert parsed[0].notes == ()


def test_fatal_errors_and_unknown_words_map_conservatively() -> None:
    assert DiagnosticSeverity.parse("fatal error") is DiagnosticSeverity.ERROR
    assert DiagnosticSeverity.parse("REMARK") is DiagnosticSeverity.REMARK
    # An unrecognised severity becomes the weakest claim available.
    assert DiagnosticSeverity.parse("catastrophe") is DiagnosticSeverity.WARNING


# --------------------------------------------------------------- unmapped


def test_an_unknown_rule_id_maps_to_no_cwe_and_raises_nothing() -> None:
    """T-07-17: a check added upstream tomorrow still reaches a human."""
    profile = load_profile()
    assert profile.cwe_for("bugprone-future-check-2030") == []
    assert profile.cwe_for("some-vendor-check-nobody-has-heard-of") == []
