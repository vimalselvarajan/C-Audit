"""``clang-tidy``: invocation and ``--export-fixes`` YAML parsing.

The YAML is read rather than the console output for one reason: it is the only
form in which clang-tidy states, as data, which diagnostic a note belongs to.
Notes arrive as a flat list in the text output and reconstructing the
parent-child relationship from indentation is guesswork; in the YAML, a note
is a member of its diagnostic's ``Notes``. Getting that wrong turns one defect
into four candidates and inflates every count downstream.

**A suggested fix is recorded, never applied.** clang-tidy will happily
rewrite source with ``--fix``; C Audit does not pass it, and the replacements
in the YAML become text in the provenance detail. The MVP recommends
remediations; patch generation is Phase 2.

The compile command is passed after ``--``, built from the unit's own argv, so
clang-tidy analyses exactly what the build compiles without C Audit inventing
a flag. ``argv[0]`` and the input file are dropped: everything after ``--`` is
the flag list, and LLVM's fixed compilation database supplies both itself.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Final

import yaml

from caudit.analyzers.normalize import (
    DiagnosticSeverity,
    Normalizer,
    RawDiagnostic,
    RawNote,
    relative_to_repo,
    sort_diagnostics,
)
from caudit.analyzers.profile import CheckProfile
from caudit.analyzers.runner import (
    AnalyzerRun,
    RunRequest,
    Subprocess,
    analysis_flags,
    source_argument,
    warnings_stay_warnings,
)
from caudit.errors import RegionError
from caudit.intake.plan import TranslationUnit
from caudit.model.candidate import Candidate
from caudit.model.evidence import Producer

__all__ = ["TidyAnalyzer", "parse_export_fixes"]

_TOOL_NAME: Final = "clang-tidy"


def parse_export_fixes(text: str, *, tool_version: str) -> list[RawDiagnostic]:
    """Parse a ``--export-fixes`` document into raw diagnostics.

    One caveat travels with the result: the YAML addresses source by **byte
    offset**, not by line, so ``line`` here holds an offset.
    :meth:`TidyAnalyzer._resolve_offsets` converts it against the file the
    offset refers to. Nothing downstream sees the offset form.

    Tolerant by design: a truncated file yields no diagnostics rather than an
    exception, because the caller has already recorded why the run ended badly.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(document, dict):
        return []
    parsed = (_diagnostic(entry, tool_version) for entry in _list(document.get("Diagnostics")))
    return [diagnostic for diagnostic in parsed if diagnostic is not None]


def _diagnostic(entry: object, tool_version: str) -> RawDiagnostic | None:
    if not isinstance(entry, dict):
        return None
    message = entry.get("DiagnosticMessage")
    if not isinstance(message, dict):
        return None
    path = str(message.get("FilePath") or "")
    if not path:
        return None
    return RawDiagnostic(
        producer=Producer.CLANG_TIDY,
        tool_name=_TOOL_NAME,
        tool_version=tool_version,
        rule_id=str(entry.get("DiagnosticName") or ""),
        message=str(message.get("Message") or ""),
        path=path,
        # Offsets for now; the analyzer resolves them against the file.
        line=_int(message.get("FileOffset")),
        severity=DiagnosticSeverity.parse(str(entry.get("Level") or "warning")),
        notes=tuple(_notes(entry)),
        fix=_fix(message),
    )


def _notes(entry: dict[str, Any]) -> list[RawNote]:
    """Notes belong to their diagnostic, never to the candidate stream."""
    notes: list[RawNote] = []
    for note in _list(entry.get("Notes")):
        if not isinstance(note, dict):
            continue
        path = str(note.get("FilePath") or "")
        if not path:
            continue
        notes.append(
            RawNote(
                path=path,
                line=_int(note.get("FileOffset")),
                message=str(note.get("Message") or ""),
            )
        )
    return notes


def _fix(message: dict[str, Any]) -> str | None:
    """Every suggested replacement, rendered as text. Nothing is written."""
    parts: list[str] = []
    for replacement in _list(message.get("Replacements")):
        if not isinstance(replacement, dict):
            continue
        path = str(replacement.get("FilePath") or "?")
        offset = _int(replacement.get("Offset"))
        length = _int(replacement.get("Length"))
        text = str(replacement.get("ReplacementText") or "")
        parts.append(f"{path}@{offset}+{length} -> {text!r}")
    return "; ".join(parts) or None


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


# ------------------------------------------------------------------ analyzer


class TidyAnalyzer:
    """Runs ``clang-tidy`` over one translation unit and parses its fixes file."""

    name = Producer.CLANG_TIDY
    tool_name = _TOOL_NAME

    def __init__(
        self,
        *,
        profile: CheckProfile,
        normalizer: Normalizer,
        clang_tidy: str = "clang-tidy",
        tool_version: str = "unknown",
        subprocess_runner: Subprocess | None = None,
    ) -> None:
        self._profile = profile
        self._normalizer = normalizer
        self._clang_tidy = clang_tidy
        self.tool_version = tool_version
        self._subprocess = subprocess_runner

    def command(self, unit: TranslationUnit, output: Path) -> list[str]:
        """The exact argv. ``--fix`` is absent, and always will be."""
        return [
            self._clang_tidy,
            "--quiet",
            f"--checks={self._profile.tidy_checks_argument()}",
            f"--export-fixes={output}",
            source_argument(unit),
            "--",
            *analysis_flags(unit),
            *warnings_stay_warnings(),
            *self._profile.diagnostic_flags,
        ]

    def run(self, unit: TranslationUnit, timeout_s: float, *, out_dir: Path) -> AnalyzerRun:
        slug = str(unit.file).replace("/", "__")
        output = out_dir / f"{slug}.tidy.yaml"
        return RunRequest(
            analyzer=self.name,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            profile_version=self._profile.version,
            unit=unit,
            command=self.command(unit, output),
            raw_output_path=output,
            log_path=out_dir / f"{slug}.tidy.log",
            subprocess_runner=self._subprocess,
        ).execute(timeout_s)

    def parse(self, run: AnalyzerRun) -> list[Candidate]:
        text = run.read_raw_output()
        if not text:
            return []
        resolved = [
            self._resolve_offsets(diagnostic, run)
            for diagnostic in parse_export_fixes(text, tool_version=run.tool_version)
        ]
        return self._normalizer.to_candidates(
            sort_diagnostics(resolved), base=run.working_directory
        )

    def _resolve_offsets(self, diagnostic: RawDiagnostic, run: AnalyzerRun) -> RawDiagnostic:
        """Turn clang-tidy's byte offsets into 1-based line numbers.

        A file the store cannot read leaves the offset in place as line 1,
        which the normalizer then rejects as an unreadable region rather than
        pointing a citation at a line that does not mean what it says.
        """
        return replace(
            diagnostic,
            line=self._line_for(diagnostic.path, diagnostic.line, run),
            end_line=None,
            notes=tuple(
                replace(note, line=self._line_for(note.path, note.line, run))
                for note in diagnostic.notes
            ),
            unit=run.unit,
        )

    def _line_for(self, path: str, offset: int, run: AnalyzerRun) -> int:
        relative = relative_to_repo(path, self._normalizer.repo_root, base=run.working_directory)
        if relative is None:
            return 1
        try:
            return self._normalizer.store.byte_to_line(relative, offset)
        except (RegionError, ValueError):
            return 1
