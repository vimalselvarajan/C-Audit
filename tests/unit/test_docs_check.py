from __future__ import annotations

from pathlib import Path

from tools.check_docs import (
    DocumentationError,
    agent_pointer_errors,
    check,
    link_errors,
    markdown_documents,
    source_of_truth_errors,
)

_AGENT_POINTER_CONTENT = (
    "# Agent Instructions\n\n"
    "See the canonical [agent documentation](agents_docs/README.md) "
    "for project instructions.\n"
)


def test_repository_documentation_is_canonical_and_linked() -> None:
    assert check(Path(__file__).resolve().parents[2]) == []


def test_link_errors_report_missing_relative_destination(tmp_path: Path) -> None:
    document = tmp_path / "guide.md"
    document.write_text("[missing](missing.md)\n", encoding="utf-8")

    assert link_errors(tmp_path, [document]) == [
        DocumentationError(document, "broken internal link: missing.md")
    ]


def test_markdown_documents_include_agent_docs_and_validate_their_links(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "agents_docs"
    directory.mkdir()
    document = directory / "README.md"
    document.write_text("[missing](missing.md)\n", encoding="utf-8")

    assert document in markdown_documents(tmp_path)
    assert DocumentationError(document, "broken internal link: missing.md") in link_errors(tmp_path)


def test_source_of_truth_rejects_legacy_documentation_tree(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()

    assert DocumentationError(
        tmp_path / "docs", "legacy documentation tree must not exist"
    ) in source_of_truth_errors(tmp_path)


def test_source_of_truth_requires_agent_index(tmp_path: Path) -> None:
    assert DocumentationError(
        tmp_path / "agents_docs" / "README.md",
        "required canonical documentation is missing",
    ) in source_of_truth_errors(tmp_path)


def test_agent_pointer_errors_report_missing_pointer(tmp_path: Path) -> None:
    assert DocumentationError(
        tmp_path / "AGENTS.md", "required agent pointer is missing"
    ) in agent_pointer_errors(tmp_path)


def test_agent_pointer_errors_reject_wrong_target(tmp_path: Path) -> None:
    pointer = tmp_path / "AGENTS.md"
    pointer.write_text(
        "# Agent Instructions\n\nSee [legacy instructions](CLAUDE.md).\n",
        encoding="utf-8",
    )

    assert DocumentationError(
        pointer, "must point directly to agents_docs/README.md"
    ) in agent_pointer_errors(tmp_path)


def test_agent_pointer_errors_reject_additional_content(tmp_path: Path) -> None:
    pointer = tmp_path / "AGENTS.md"
    pointer.write_text(
        f"{_AGENT_POINTER_CONTENT}\nDuplicated project guidance.\n",
        encoding="utf-8",
    )

    assert DocumentationError(
        pointer, "must contain only the canonical agent pointer"
    ) in agent_pointer_errors(tmp_path)
