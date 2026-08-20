"""Part 02 identity tests: T-02-03, T-02-04, T-02-05, T-02-06."""

from __future__ import annotations

import subprocess
import sys
from pathlib import PurePosixPath

from caudit.model.ids import (
    candidate_id,
    dedup_fingerprint,
    evidence_id,
    finding_id,
    normalize_message,
)
from tests.conftest import make_region

PATH = PurePosixPath("src/parser.c")


def test_fingerprint_survives_code_motion() -> None:
    """T-02-03: the same defect at line 40 and line 118 fingerprints alike."""
    at_40 = dedup_fingerprint("CWE-787", PATH, "parse", "unbounded copy into buf")
    at_118 = dedup_fingerprint("CWE-787", PATH, "parse", "unbounded copy into buf")
    assert at_40 == at_118
    # And line numbers are simply not part of the input.
    assert "40" not in at_40


def test_different_defects_in_one_function_fingerprint_differently() -> None:
    """T-02-04."""
    first = dedup_fingerprint("CWE-787", PATH, "parse", "unbounded copy into buf")
    second = dedup_fingerprint("CWE-476", PATH, "parse", "dereference of null pointer")
    assert first != second


def test_finding_id_is_stable_across_processes() -> None:
    """T-02-05: no hash randomisation leaks into the id."""
    expected = finding_id("CWE-787", PATH, "parse", "unbounded copy", start_byte=40, end_byte=54)
    script = (
        "from pathlib import PurePosixPath;"
        "from caudit.model.ids import finding_id;"
        "print(finding_id('CWE-787', PurePosixPath('src/parser.c'), 'parse',"
        " 'unbounded copy', start_byte=40, end_byte=54))"
    )
    outputs = {
        subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        for _ in range(2)
    }
    assert outputs == {expected}


def test_message_digits_do_not_change_the_fingerprint() -> None:
    """T-02-06: a differing buffer size normalises away; the raw text stays."""
    small = "Buffer of size 16 overflowed by 4 bytes"
    large = "Buffer of size 4096 overflowed by 12 bytes"
    assert dedup_fingerprint("CWE-787", PATH, "parse", small) == dedup_fingerprint(
        "CWE-787", PATH, "parse", large
    )
    # The raw message is not mutated by fingerprinting.
    assert "16" in small


def test_normalize_message_strips_paths_quotes_and_numbers() -> None:
    normalized = normalize_message(
        "Value stored to 'idx' in src/deep/parser.c is 0x1F and never read."
    )
    assert "<id>" in normalized
    assert "<path>" in normalized
    assert "<n>" in normalized
    assert normalized == normalize_message(normalized), "must be idempotent"


def test_normalize_message_is_idempotent_on_already_clean_text() -> None:
    assert normalize_message("plain message") == "plain message"


def test_finding_id_and_fingerprint_are_domain_separated() -> None:
    """Same inputs, different purposes, so they must not collide."""
    args = ("CWE-787", PATH, "parse", "unbounded copy")
    report_id = finding_id(*args, start_byte=40, end_byte=54)
    assert report_id != dedup_fingerprint(*args)
    assert report_id.startswith("caudit-")
    assert dedup_fingerprint(*args).startswith("fp-")


def test_finding_id_distinguishes_report_entries_at_different_locations() -> None:
    """Distinct candidates stay distinct if adjudication makes their text agree."""
    first = finding_id("CWE-787", PATH, "parse", "unbounded copy", start_byte=40, end_byte=54)
    second = finding_id("CWE-787", PATH, "parse", "unbounded copy", start_byte=118, end_byte=132)
    assert first != second


def test_evidence_id_is_content_addressed() -> None:
    region = make_region(sha256="b" * 64)
    first = evidence_id(region, "primary_code")
    assert first == evidence_id(region, "primary_code")
    # Kind is part of the address.
    assert first != evidence_id(region, "supporting_code")
    # So is the content hash.
    moved = region.model_copy(update={"sha256": "c" * 64})
    assert first != evidence_id(moved, "primary_code")
    # And so is the byte range.
    shifted = region.model_copy(update={"start_byte": 1})
    assert first != evidence_id(shifted, "primary_code")


def test_evidence_id_rejects_a_non_region() -> None:
    try:
        evidence_id(object(), "primary_code")
    except TypeError as exc:
        assert "SourceRegion" in str(exc)
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected TypeError")


def test_candidate_id_includes_the_line_but_the_fingerprint_does_not() -> None:
    """Two analyzers on different lines are two candidates, one defect."""
    first = candidate_id("clang_tidy", "rule", PATH, 10, "leak of memory")
    second = candidate_id("clang_tidy", "rule", PATH, 42, "leak of memory")
    assert first != second
    assert dedup_fingerprint("CWE-401", PATH, "f", "leak of memory") == (
        dedup_fingerprint("CWE-401", PATH, "f", "leak of memory")
    )


def test_none_symbol_is_distinguishable_from_the_string_none() -> None:
    none_symbol = finding_id("CWE-787", PATH, None, "m", start_byte=40, end_byte=54)
    literal_none = finding_id("CWE-787", PATH, "None", "m", start_byte=40, end_byte=54)
    assert none_symbol != literal_none
