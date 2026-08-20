"""Part 08 determinism tests: T-08-08, T-08-09, T-08-10, T-08-15.

Covers AC-08-7 and AC-08-11. Two runs over identical inputs must produce
byte-identical ``report.md`` and ``results.sarif`` — which is only true if
neither artifact contains a clock reading, a duration, a machine-specific
path, or an iteration order that depends on how the findings arrived.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path
from typing import Any

from caudit.model.finding import Limitation, LimitationKind
from caudit.report.manifest import path_redactor
from caudit.report.markdown import render_markdown
from caudit.report.sarif import render_sarif
from caudit.report.sections import ReportSections, sort_findings
from caudit.report.service import REPORT_MD, RESULTS_SARIF, RUN_MANIFEST, write_report
from tests.conftest import (
    DEMO_DIAGNOSTICS,
    demo_coverage,
    demo_manifest,
    demo_sections,
    write_demo_repo,
)

#: A path that is absolute in either of the two shapes the plan names.
_ABSOLUTE = re.compile(r"(?:^|[\s\"'`(])(/[^\s\"'`)]+|[A-Za-z]:\\\\?[^\s\"'`)]*)")


def _render_both(root: Path) -> tuple[str, str]:
    sections = demo_sections(root)
    manifest = demo_manifest(root, sections)
    return render_markdown(sections, manifest), render_sarif(sections, manifest)


# ---------------------------------------------------------------- T-08-08


def test_two_runs_over_the_same_inputs_are_byte_identical(tmp_path: Path) -> None:
    """T-08-08: the whole point of putting timestamps only in the manifest."""
    root = write_demo_repo(tmp_path / "demo")
    first_md, first_sarif = _render_both(root)
    second_md, second_sarif = _render_both(root)

    assert first_md == second_md
    assert first_sarif == second_sarif


def test_written_files_are_byte_identical_across_two_writes(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    manifest = demo_manifest(root, sections)

    first = write_report(sections, manifest, tmp_path / "out-one")
    second = write_report(sections, manifest, tmp_path / "out-two")

    for left, right in zip(first.paths, second.paths, strict=True):
        assert left.read_bytes() == right.read_bytes(), left.name
    assert [path.name for path in first.paths] == [REPORT_MD, RESULTS_SARIF, RUN_MANIFEST]


def test_report_text_ends_in_exactly_one_newline(tmp_path: Path) -> None:
    """A trailing-whitespace difference is a byte difference."""
    markdown, sarif = _render_both(write_demo_repo(tmp_path / "demo"))
    for text in (markdown, sarif):
        assert text.endswith("\n")
        assert not text.endswith("\n\n")


# ---------------------------------------------------------------- T-08-09


def test_the_same_repository_at_two_paths_renders_identically(tmp_path: Path) -> None:
    """T-08-09, AC-08-11: only the manifest may notice where the tree lives."""
    here = write_demo_repo(tmp_path / "one" / "demo")
    there = write_demo_repo(tmp_path / "two" / "demo")

    assert _render_both(here) == _render_both(there)

    # The manifest is the one artifact allowed to differ, and it differs only
    # in the field that records where the run happened.
    left = demo_manifest(here, demo_sections(here))
    right = demo_manifest(there, demo_sections(there))
    assert left.repository_root != right.repository_root
    assert left.cited_region_hashes == right.cited_region_hashes


# ---------------------------------------------------------------- T-08-10


def test_shuffled_input_produces_the_same_sorted_output(tmp_path: Path) -> None:
    """T-08-10: the sort key is total, so input order cannot survive it."""
    root = write_demo_repo(tmp_path / "demo")
    reference = demo_sections(root)
    baseline_md, baseline_sarif = _render_both(root)

    rng = random.Random(20260812)
    for _attempt in range(5):
        shuffled = list(DEMO_DIAGNOSTICS)
        rng.shuffle(shuffled)
        sections = demo_sections(root, diagnostics=shuffled)
        manifest = demo_manifest(root, sections)

        assert [f.finding_id for f in sections.confirmed] == [
            f.finding_id for f in reference.confirmed
        ]
        assert render_markdown(sections, manifest) == baseline_md
        assert render_sarif(sections, manifest) == baseline_sarif


def test_sorting_an_already_sorted_list_changes_nothing(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    ordered = demo_sections(root).confirmed
    assert sort_findings(ordered) == ordered
    assert sort_findings(list(reversed(ordered))) == ordered


# ---------------------------------------------------------------- T-08-15


def _strings(node: Any) -> list[str]:
    """Every string value anywhere in a JSON document."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [text for value in node.values() for text in _strings(value)]
    if isinstance(node, list):
        return [text for value in node for text in _strings(value)]
    return []


def test_no_absolute_path_appears_outside_the_manifest(tmp_path: Path) -> None:
    """T-08-15, AC-08-11: neither the tmp root nor any rooted path at all."""
    root = write_demo_repo(tmp_path / "demo")
    markdown, sarif = _render_both(root)

    for text in (markdown, sarif):
        assert str(root) not in text
        assert str(tmp_path) not in text

    for line in markdown.splitlines():
        assert not line.startswith("/"), line
    assert not _ABSOLUTE.search(markdown), _ABSOLUTE.search(markdown)

    for value in _strings(json.loads(sarif)):
        assert not value.startswith("/"), value
        assert not re.match(r"^[A-Za-z]:\\", value), value


def test_the_manifest_does_keep_the_absolute_path(tmp_path: Path) -> None:
    """The rule is "only in the manifest", not "nowhere"."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    artifacts = write_report(sections, demo_manifest(root, sections), tmp_path / "out")

    manifest = json.loads(artifacts.run_manifest.read_text(encoding="utf-8"))
    assert manifest["repository_root"] == str(root)
    assert manifest["started_at"]


def test_a_limitation_naming_the_absolute_root_is_redacted(tmp_path: Path) -> None:
    """Intake really does write the absolute root into a limitation detail.

    ``revision_unavailable`` names the tree it could not pin, and it names it
    absolutely, which is correct for a message a user reads on their terminal
    and wrong for an artifact meant to be identical on two machines. The
    redaction happens at the rendering boundary, so no upstream part has to
    know about AC-08-11.
    """
    root = write_demo_repo(tmp_path / "demo")
    limitation = Limitation(
        kind=LimitationKind.REVISION_UNAVAILABLE,
        detail=f"{root} is not inside a git work tree, so the revision cannot be pinned",
        affects=str(root),
    )
    sections = demo_sections(root, limitations=[limitation])
    manifest = demo_manifest(root, sections)

    markdown = render_markdown(sections, manifest)
    sarif = render_sarif(sections, manifest)

    assert str(root) not in markdown
    assert str(root) not in sarif
    # Redacted, not deleted: the limitation is still there and still legible.
    assert "is not inside a git work tree" in markdown
    assert "`demo`" in markdown
    for value in _strings(json.loads(sarif)):
        assert not value.startswith("/"), value


def test_a_root_with_no_name_of_its_own_is_left_alone(tmp_path: Path) -> None:
    """Substituting "/" would rewrite every path in the document."""
    root = write_demo_repo(tmp_path / "demo")
    sections = demo_sections(root)
    manifest = demo_manifest(root, sections, repository_root="/", compile_commands_path=None)

    redact = path_redactor(manifest)
    assert redact("src/alpha.c is at /somewhere/else") == "src/alpha.c is at /somewhere/else"


def test_an_empty_run_is_also_path_free(tmp_path: Path) -> None:
    root = write_demo_repo(tmp_path / "demo")
    sections = ReportSections(coverage=demo_coverage())
    manifest = demo_manifest(root, sections)

    assert str(root) not in render_markdown(sections, manifest)
    assert str(root) not in render_sarif(sections, manifest)
