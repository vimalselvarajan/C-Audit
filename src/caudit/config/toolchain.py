"""Toolchain discovery, version parsing, and requirement checks.

The spec refuses to guess build flags. This module applies the same posture
to the toolchain itself: a tool that is missing, or whose version falls
outside the supported range, is an :class:`~caudit.errors.ToolchainError`
with a copy-pasteable install command — never a silent fallback to whatever
happens to be on ``PATH``.

Every version discovered here is a fact the run manifest records (part 08).
A run whose analyzer versions are unknown is not reproducible.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from importlib import metadata
from pathlib import Path
from typing import Final

from caudit.errors import ToolchainError

__all__ = [
    "REQUIRED_TOOLS",
    "ToolInfo",
    "ToolRequirement",
    "ToolStatus",
    "ToolchainProbe",
    "VersionSpec",
    "parse_version",
    "requirements_for",
]

_VERSION_RE: Final = re.compile(r"\bversion\s+(\d+)\.(\d+)(?:\.(\d+))?|\b(\d+)\.(\d+)\.(\d+)\b")


def parse_version(text: str) -> str | None:
    """Normalise a ``--version`` banner to ``major.minor.patch``.

    Handles the shapes Clang actually emits::

        Ubuntu clang version 18.1.3 (1ubuntu1)
        LLVM (http://llvm.org/): LLVM version 18.1.3

    Returns ``None`` when nothing version-shaped is present; the caller
    records that as ``unknown`` and treats the tool as unsatisfied.
    """
    match = _VERSION_RE.search(text)
    if match is None:
        return None
    if match.group(1) is not None:
        major, minor, patch = match.group(1), match.group(2), match.group(3) or "0"
    else:
        major, minor, patch = match.group(4), match.group(5), match.group(6)
    return f"{int(major)}.{int(minor)}.{int(patch)}"


@dataclass(frozen=True)
class VersionSpec:
    """An inclusive range of acceptable majors.

    A range rather than an exact pin so a user can deliberately run a newer
    LLVM; ``doctor`` still distinguishes "missing" from "outside the
    supported range" so the override is a choice, not an accident.
    """

    min_major: int
    max_major: int | None = None

    def satisfied_by(self, version: str | None) -> bool:
        if version is None:
            return False
        major = int(version.split(".", 1)[0])
        if major < self.min_major:
            return False
        return not (self.max_major is not None and major > self.max_major)

    def describe(self) -> str:
        if self.max_major is None:
            return f">= {self.min_major}"
        if self.max_major == self.min_major:
            return f"== {self.min_major}"
        return f"{self.min_major}-{self.max_major}"


class ToolStatus(StrEnum):
    """Why a tool does or does not satisfy its requirement."""

    OK = "ok"
    MISSING = "missing"
    UNPARSEABLE_VERSION = "unparseable_version"
    OUT_OF_RANGE = "out_of_range"
    PROBE_FAILED = "probe_failed"


@dataclass(frozen=True)
class ToolInfo:
    """What was discovered about one tool. Recorded in the run manifest."""

    name: str
    path: Path | None
    version: str | None
    satisfies_requirement: bool
    install_hint: str
    status: ToolStatus = ToolStatus.OK
    required: bool = True
    detail: str = ""

    @property
    def version_display(self) -> str:
        return self.version or "unknown"


@dataclass(frozen=True)
class ToolRequirement:
    """How to find one tool and how to read its version."""

    name: str
    spec: VersionSpec
    version_args: tuple[str, ...] = ("--version",)
    #: scan-build has no version flag of its own; it ships with the Clang it
    #: came from, so presence is what we can honestly check.
    version_required: bool = True
    required: bool = True
    purpose: str = ""


def requirements_for(llvm_major: int) -> dict[str, ToolRequirement]:
    """The tools C Audit needs, pinned against one LLVM major."""
    spec = VersionSpec(min_major=llvm_major, max_major=llvm_major + 2)
    return {
        "clang": ToolRequirement("clang", spec, purpose="parse C translation units"),
        "clang++": ToolRequirement("clang++", spec, purpose="parse C++ translation units"),
        "clang-tidy": ToolRequirement("clang-tidy", spec, purpose="curated check profile"),
        "scan-build": ToolRequirement(
            "scan-build",
            spec,
            version_args=("-h",),
            version_required=False,
            purpose="Clang Static Analyzer driver",
        ),
        "clang-format": ToolRequirement(
            "clang-format", spec, required=False, purpose="fixture formatting only"
        ),
    }


#: The default requirement set, resolved against the configured LLVM major.
REQUIRED_TOOLS: Final[tuple[str, ...]] = ("clang", "clang++", "clang-tidy", "scan-build")

_INSTALL_HINTS: Final[Mapping[str, str]] = {
    "clang": "sudo apt-get install -y clang-{major}",
    "clang++": "sudo apt-get install -y clang-{major}",
    "clang-tidy": "sudo apt-get install -y clang-tidy-{major}",
    "scan-build": "sudo apt-get install -y clang-tools-{major}",
    "clang-format": "sudo apt-get install -y clang-format-{major}",
}

_RUNNER = Callable[[Path, Sequence[str]], str]


def _run_version_command(path: Path, args: Sequence[str]) -> str:
    completed = subprocess.run(
        [str(path), *args],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return f"{completed.stdout}\n{completed.stderr}"


class ToolchainProbe:
    """Discovers tools on ``PATH`` and checks them against their pins."""

    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        which: Callable[[str, str | None], str | None] | None = None,
        runner: _RUNNER | None = None,
        llvm_major: int = 18,
    ) -> None:
        self._env = env
        self._which = which or (lambda name, path: shutil.which(name, path=path))
        self._runner = runner or _run_version_command
        self._llvm_major = llvm_major
        self._last: dict[str, ToolInfo] = {}

    # ---------------------------------------------------------------- probe

    def probe(self, required: Mapping[str, VersionSpec | ToolRequirement]) -> list[ToolInfo]:
        """Discover each named tool. Never raises for a missing tool."""
        results: list[ToolInfo] = []
        for name, entry in required.items():
            requirement = (
                entry
                if isinstance(entry, ToolRequirement)
                else ToolRequirement(name=name, spec=entry)
            )
            results.append(self._probe_one(requirement))
        self._last = {info.name: info for info in results}
        return results

    def probe_defaults(self) -> list[ToolInfo]:
        """Probe the standard requirement set plus the libclang wheel."""
        infos = self.probe(requirements_for(self._llvm_major))
        infos.append(self.libclang_wheel())
        return self._annotate_wheel_drift(infos)

    def _probe_one(self, requirement: ToolRequirement) -> ToolInfo:
        hint = self._install_hint(requirement.name)
        search_path = None if self._env is None else self._env.get("PATH", "")
        found = self._which(requirement.name, search_path)
        if found is None:
            return ToolInfo(
                name=requirement.name,
                path=None,
                version=None,
                satisfies_requirement=False,
                install_hint=hint,
                status=ToolStatus.MISSING,
                required=requirement.required,
                detail=f"not found on PATH (required {requirement.spec.describe()})",
            )

        path = Path(found)
        try:
            output = self._runner(path, requirement.version_args)
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolInfo(
                name=requirement.name,
                path=path,
                version=None,
                satisfies_requirement=False,
                install_hint=hint,
                status=ToolStatus.PROBE_FAILED,
                required=requirement.required,
                detail=f"could not execute {path} {' '.join(requirement.version_args)}: {exc}",
            )

        version = parse_version(output)
        if version is None:
            satisfied = not requirement.version_required
            status = ToolStatus.OK if satisfied else ToolStatus.UNPARSEABLE_VERSION
            detail = (
                "no version string available; presence is the only check for this tool"
                if satisfied
                else "version output could not be parsed; treating as unsatisfied"
            )
            return ToolInfo(
                name=requirement.name,
                path=path,
                version=None,
                satisfies_requirement=satisfied,
                install_hint=hint,
                status=status,
                required=requirement.required,
                detail=detail,
            )

        if requirement.spec.satisfied_by(version):
            return ToolInfo(
                name=requirement.name,
                path=path,
                version=version,
                satisfies_requirement=True,
                install_hint=hint,
                status=ToolStatus.OK,
                required=requirement.required,
                detail="",
            )
        return ToolInfo(
            name=requirement.name,
            path=path,
            version=version,
            satisfies_requirement=False,
            install_hint=hint,
            status=ToolStatus.OUT_OF_RANGE,
            required=requirement.required,
            detail=(f"found {version}, supported range is major {requirement.spec.describe()}"),
        )

    def libclang_wheel(self) -> ToolInfo:
        """The PyPI ``libclang`` wheel used for indexing in part 06."""
        spec = VersionSpec(min_major=self._llvm_major, max_major=self._llvm_major + 2)
        try:
            version = metadata.version("libclang")
        except metadata.PackageNotFoundError:
            return ToolInfo(
                name="libclang (python wheel)",
                path=None,
                version=None,
                satisfies_requirement=False,
                install_hint="pip install 'libclang>=18.1.1,<19'",
                status=ToolStatus.MISSING,
                detail="the wheel bundles its own shared library; no system LLVM needed",
            )
        normalised = parse_version(version) or version
        satisfied = spec.satisfied_by(normalised)
        return ToolInfo(
            name="libclang (python wheel)",
            path=None,
            version=normalised,
            satisfies_requirement=satisfied,
            install_hint="pip install 'libclang>=18.1.1,<19'",
            status=ToolStatus.OK if satisfied else ToolStatus.OUT_OF_RANGE,
            detail="" if satisfied else f"found {normalised}, supported {spec.describe()}",
        )

    @staticmethod
    def _annotate_wheel_drift(infos: list[ToolInfo]) -> list[ToolInfo]:
        """Warn when the wheel and system clang-tidy majors disagree.

        They can produce subtly different ASTs, so the manifest records both
        and ``doctor`` says so out loud rather than leaving it to be
        discovered through a confusing result.
        """
        by_name = {info.name: info for info in infos}
        wheel = by_name.get("libclang (python wheel)")
        tidy = by_name.get("clang-tidy")
        if wheel is None or tidy is None or wheel.version is None or tidy.version is None:
            return infos
        if wheel.version.split(".")[0] == tidy.version.split(".")[0]:
            return infos
        note = (
            f"major differs from clang-tidy {tidy.version}; indexing and analysis "
            "may disagree on ASTs"
        )
        return [
            replace(info, detail=(f"{info.detail} {note}".strip()))
            if info.name == wheel.name
            else info
            for info in infos
        ]

    # -------------------------------------------------------------- require

    def require(self, *names: str) -> None:
        """Raise :class:`ToolchainError` if any named tool is unsatisfied."""
        catalogue = requirements_for(self._llvm_major)
        wanted = {
            name: catalogue.get(name, ToolRequirement(name, VersionSpec(self._llvm_major)))
            for name in names
        }
        infos = [
            self._last.get(name) or self._probe_one(requirement)
            for name, requirement in wanted.items()
        ]
        unsatisfied = [info for info in infos if not info.satisfies_requirement]
        if not unsatisfied:
            return
        lines = [f"  - {info.name}: {info.detail or 'unsatisfied'}" for info in unsatisfied]
        hints = "\n".join(
            f"  {hint}" for hint in dict.fromkeys(info.install_hint for info in unsatisfied)
        )
        raise ToolchainError(
            "Required toolchain components are missing or unsupported:\n" + "\n".join(lines),
            hint=(
                f"Install them with:\n{hints}\n\n"
                "See my_docs/guides/setup.md for the full procedure."
            ),
        )

    def _install_hint(self, name: str) -> str:
        template = _INSTALL_HINTS.get(name, "see my_docs/guides/setup.md")
        return template.format(major=self._llvm_major)
