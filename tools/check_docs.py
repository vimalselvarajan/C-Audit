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
_ROOT_DOCUMENTS = ("README.md", "CLAUDE.md")
_REQUIRED_DOCUMENTS = (
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
    docs = repository / "my_docs"
    if docs.is_dir():
        documents.extend(sorted(docs.rglob("*.md")))
    return tuple(path for path in documents if path.is_file())


def _destination(raw: str) -> str:
    """Strip an optional Markdown title or angle brackets from a destination."""
    destination = raw.strip()
    if destination.startswith("<") and destination.endswith(">"):
        return destination[1:-1]
    return destination.split(maxsplit=1)[0]


def _is_external(destination: str) -> bool:
    return bool(urlsplit(destination).scheme) or destination.startswith("//")


def link_errors(
    repository: Path, documents: Iterable[Path] | None = None
) -> list[DocumentationError]:
    """Return every local Markdown destination that cannot be resolved."""
    errors: list[DocumentationError] = []
    for document in documents or markdown_documents(repository):
        for match in _LINK.finditer(document.read_text(encoding="utf-8")):
            destination = _destination(match.group(1))
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


def source_of_truth_errors(repository: Path) -> list[DocumentationError]:
    """Ensure my_docs, not the legacy docs tree, is canonical."""
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
    return [*source_of_truth_errors(repository), *link_errors(repository)]


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    errors = check(repository)
    if not errors:
        print("documentation links and source of truth are valid")
        return 0
    for error in errors:
        print(f"error: {error.render(repository)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
