from __future__ import annotations

from pathlib import Path

from tools.check_docs import DocumentationError, check, link_errors, source_of_truth_errors


def test_repository_documentation_is_canonical_and_linked() -> None:
    assert check(Path(__file__).resolve().parents[2]) == []


def test_link_errors_report_missing_relative_destination(tmp_path: Path) -> None:
    document = tmp_path / "guide.md"
    document.write_text("[missing](missing.md)\n", encoding="utf-8")

    assert link_errors(tmp_path, [document]) == [
        DocumentationError(document, "broken internal link: missing.md")
    ]


def test_source_of_truth_rejects_legacy_documentation_tree(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()

    assert DocumentationError(
        tmp_path / "docs", "legacy documentation tree must not exist"
    ) in source_of_truth_errors(tmp_path)
