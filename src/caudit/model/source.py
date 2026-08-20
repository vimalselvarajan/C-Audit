"""Source locations: the smallest thing a claim can point at.

Path handling is the first line of defence against a citation that points
outside the scanned tree. Absolute paths, ``..`` segments, and Windows
separators are rejected here, at the model boundary, before any component
gets a chance to open a file (part 03 checks containment again after
``realpath``, because a symlink can escape without any of those shapes).
"""

from __future__ import annotations

import ntpath
from pathlib import PurePosixPath
from typing import Annotated, Any, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

__all__ = ["RegionHash", "Sha256", "SourceRegion", "Symbol", "normalize_repo_path"]

#: Lowercase hex sha256. Uppercase is rejected so two spellings of one hash
#: can never compare unequal.
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

RegionHash = Sha256
"""Alias used where the value is specifically a region's content hash."""


def normalize_repo_path(value: str | PurePosixPath) -> PurePosixPath:
    """Validate a repository-relative POSIX path, or raise ``ValueError``."""
    text = str(value)
    if not text:
        raise ValueError("path must not be empty")
    if "\\" in text or ntpath.splitdrive(text)[0]:
        raise ValueError(f"path must use POSIX separators and no drive letter: {text!r}")
    path = PurePosixPath(text)
    if path.is_absolute():
        raise ValueError(f"path must be repository-relative, not absolute: {text!r}")
    if any(part == ".." for part in path.parts):
        raise ValueError(f"path must not contain '..' segments: {text!r}")
    if any(part == "." for part in path.parts):
        path = PurePosixPath(*[part for part in path.parts if part != "."])
    if not path.parts:
        raise ValueError(f"path resolves to nothing: {text!r}")
    return path


class Symbol(BaseModel):
    """A named program entity a finding can be attached to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    #: ``function``, ``method``, ``variable``, ``macro``, ``type``, ``field``.
    kind: str = Field(min_length=1)
    #: Mangled or fully-qualified name when the index can supply one.
    qualified_name: str | None = None
    #: Populated by the part 06 index; ``None`` for textual v1 resolution.
    usr: str | None = None


class SourceRegion(BaseModel):
    """A byte- and line-addressed span of one file, with its content hash.

    Both addressings are stored so a mismatch between them is detectable:
    lines are 1-based inclusive on both ends (matching Clang and SARIF),
    bytes are half-open ``[start_byte, end_byte)``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: PurePosixPath
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_byte: int = Field(ge=0)
    end_byte: int = Field(ge=0)
    sha256: Sha256

    @field_validator("path", mode="before")
    @classmethod
    def _validate_path(cls, value: Any) -> str:
        """Normalize, then hand pydantic a string.

        Returning a ``PurePosixPath`` here would work when validating Python
        objects and fail when validating JSON, where the core path validator
        only accepts strings — so a region could be serialized and never read
        back. Parts 08 and 11 both do exactly that.
        """
        if isinstance(value, PurePosixPath | str):
            return str(normalize_repo_path(value))
        raise ValueError(f"path must be a string or PurePosixPath, got {type(value).__name__}")

    @model_validator(mode="after")
    def _check_ordering(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError(f"end_line {self.end_line} precedes start_line {self.start_line}")
        if self.end_byte < self.start_byte:
            raise ValueError(f"end_byte {self.end_byte} precedes start_byte {self.start_byte}")
        return self

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1

    @property
    def byte_length(self) -> int:
        return self.end_byte - self.start_byte

    def describe(self) -> str:
        """``src/x.c:10-12`` — the form used in reports and error details."""
        if self.start_line == self.end_line:
            return f"{self.path}:{self.start_line}"
        return f"{self.path}:{self.start_line}-{self.end_line}"
