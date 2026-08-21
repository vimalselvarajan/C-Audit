#!/usr/bin/env python3
"""Verify the canonical documentation tree and its internal Markdown links."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
_AGENT_INDEX = "agents_docs/README.md"
_AGENT_POINTERS = ("AGENTS.md", "AGNETS.md", "AGNETS.md.orig", "CLAUDE.md")
_AGENT_POINTER_CONTENT = (
    "# Agent Instructions\n\n"
    "See the canonical [agent documentation](agents_docs/README.md) "
    "for project instructions.\n"
)
_ROOT_DOCUMENTS = ("README.md", *_AGENT_POINTERS)
_REQUIRED_DOCUMENTS = (
    _AGENT_INDEX,
    "my_docs/specification/core_idea.md",
    "my_docs/project/evaluation-results.md",
    "my_docs/project/project-gaps.md",
    "my_docs/guides/setup.md",
    "my_docs/plan/00-overview.md",
)


@dataclass(frozen=True)
class DocumentationError:
    """One actionable documentation contract failure."""

    path: Path
    message: str

    def render(self, repository: Path) -> str:
        return f"{self.path.relative_to(repository)}: {self.message}"


def markdown_documents(repository: Path) -> tuple[Path, ...]:
    """Return committed Markdown sources whose relative links must resolve."""
    documents = [repository / name for name in _ROOT_DOCUMENTS]
    for directory_name in ("agents_docs", "my_docs"):
        directory = repository / directory_name
        if directory.is_dir():
            documents.extend(sorted(directory.rglob("*.md")))
    return tuple(path for path in documents if path.is_file())


def _destination(raw: str) -> str:
    """Strip an optional Markdown title or angle brackets from a destination."""
    destination = raw.strip()
    if destination.startswith("<") and destination.endswith(">"):
        return destination[1:-1]
    return destination.split(maxsplit=1)[0]


def _is_external(destination: str) -> bool:
    return bool(urlsplit(destination).scheme) or destination.startswith("//")


def _destinations(document: Path) -> tuple[str, ...]:
    """Return normalized Markdown link destinations from one document."""
    contents = document.read_text(encoding="utf-8")
    return tuple(_destination(match.group(1)) for match in _LINK.finditer(contents))


def link_errors(
    repository: Path, documents: Iterable[Path] | None = None
) -> list[DocumentationError]:
    """Return every local Markdown destination that cannot be resolved."""
    errors: list[DocumentationError] = []
    for document in documents or markdown_documents(repository):
        for destination in _destinations(document):
            path_part = unquote(destination.split("#", maxsplit=1)[0])
            if not path_part or _is_external(destination):
                continue
            target = (document.parent / path_part).resolve()
            try:
                target.relative_to(repository.resolve())
            except ValueError:
                errors.append(
                    DocumentationError(document, f"link escapes repository: {destination}")
                )
            else:
                if not target.exists():
                    errors.append(
                        DocumentationError(document, f"broken internal link: {destination}")
                    )
    return errors


def agent_pointer_errors(repository: Path) -> list[DocumentationError]:
    """Require every compatibility file to be a minimal direct agent-doc pointer."""
    errors: list[DocumentationError] = []
    for name in _AGENT_POINTERS:
        path = repository / name
        if not path.is_file():
            errors.append(DocumentationError(path, "required agent pointer is missing"))
            continue
        if _destinations(path) != (_AGENT_INDEX,):
            errors.append(DocumentationError(path, f"must point directly to {_AGENT_INDEX}"))
            continue
        if path.read_text(encoding="utf-8") != _AGENT_POINTER_CONTENT:
            errors.append(DocumentationError(path, "must contain only the canonical agent pointer"))
    return errors


def source_of_truth_errors(repository: Path) -> list[DocumentationError]:
    """Ensure the canonical agent and product documentation roots exist."""
    errors: list[DocumentationError] = []
    legacy = repository / "docs"
    if legacy.exists():
        errors.append(DocumentationError(legacy, "legacy documentation tree must not exist"))
    for name in _REQUIRED_DOCUMENTS:
        path = repository / name
        if not path.is_file():
            errors.append(DocumentationError(path, "required canonical documentation is missing"))
    return errors


def check(repository: Path) -> list[DocumentationError]:
    """Run the documentation contracts without writing files."""
    return [
        *source_of_truth_errors(repository),
        *agent_pointer_errors(repository),
        *link_errors(repository),
    ]


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    errors = check(repository)
    if not errors:
        print("documentation links, pointers, and sources of truth are valid")
        return 0
    for error in errors:
        print(f"error: {error.render(repository)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
