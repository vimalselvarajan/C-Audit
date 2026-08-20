"""Compile diagnostics: what the compiler itself says about the unit.

The cheapest candidate source in the pipeline and the one most often thrown
away. ``-Wformat-security`` alone names a whole weakness family, and the
compiler has already done the parse.

**Two formats, and a deviation from the plan worth stating.** The plan names
``-fdiagnostics-format=json``. That flag is GCC's; Clang's
``-fdiagnostics-format=`` accepts ``clang``/``msvc``/``vi``, not ``json``, and
C Audit pins Clang. Both parsers are implemented — the JSON one against GCC's
documented diagnostic schema, the text one against Clang's
``file:line:col: severity: message [-Wflag]`` form — and the profile's
``diagnostics.format`` selects between them, defaulting to ``text`` so the
default configuration works with the compiler this project actually pins. A
GCC-driven build sets ``json`` and gets structured notes instead of
reconstructed ones.

Notes attach to their parent diagnostic in both formats: GCC nests them under
``children``, and Clang emits them as ``note:`` lines that follow their
diagnostic. A note is never a candidate of its own.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, Final

from caudit.analyzers.normalize import (
    DiagnosticSeverity,
    Normalizer,
    RawDiagnostic,
    RawNote,
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
from caudit.intake.plan import TranslationUnit
from caudit.model.candidate import Candidate
from caudit.model.evidence import Producer

__all__ = ["DiagnosticsAnalyzer", "parse_json_diagnostics", "parse_text_diagnostics"]

_TOOL_NAME: Final = "clang"

#: ``src/x.c:17:5: warning: message [-Wformat-security]``
_TEXT_RE: Final = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>\d+):(?P<column>\d+):\s+"
    r"(?P<severity>fatal error|error|warning|note|remark):\s+(?P<message>.*?)"
    r"(?:\s+\[(?P<rule>-W[\w+.\-]+)\])?$"
)


def parse_text_diagnostics(text: str, *, tool_version: str) -> list[RawDiagnostic]:
    """Parse Clang's own diagnostic text.

    A ``note:`` line attaches to the diagnostic above it. That ordering is
    Clang's contract — a note is emitted immediately after what it explains —
    so this is reading the format, not guessing at it. A note with no preceding
    diagnostic is dropped rather than promoted.
    """
    parsed: list[RawDiagnostic] = []
    pending_notes: list[RawNote] = []
    for raw in text.splitlines():
        match = _TEXT_RE.match(raw.strip())
        if match is None:
            continue
        severity = DiagnosticSeverity.parse(match.group("severity"))
        path = match.group("path")
        line = int(match.group("line"))
        column = int(match.group("column"))
        message = match.group("message").strip()
        if severity is DiagnosticSeverity.NOTE:
            if parsed:
                pending_notes.append(RawNote(path=path, line=line, column=column, message=message))
            continue
        parsed = _flush(parsed, pending_notes)
        pending_notes = []
        parsed.append(
            RawDiagnostic(
                producer=Producer.CLANG_DIAGNOSTIC,
                tool_name=_TOOL_NAME,
                tool_version=tool_version,
                rule_id=match.group("rule") or "",
                message=message,
                path=path,
                line=line,
                column=column,
                severity=severity,
            )
        )
    return _flush(parsed, pending_notes)


def _flush(parsed: list[RawDiagnostic], notes: Sequence[RawNote]) -> list[RawDiagnostic]:
    """Attach accumulated notes to the diagnostic they followed."""
    if not parsed or not notes:
        return parsed
    parsed[-1] = replace(parsed[-1], notes=(*parsed[-1].notes, *notes))
    return parsed


def parse_json_diagnostics(text: str, *, tool_version: str) -> list[RawDiagnostic]:
    """Parse ``-fdiagnostics-format=json`` output.

    GCC's schema: a top-level array of diagnostics, each with ``kind``,
    ``message``, ``option``, ``locations[]`` (``caret``/``start``/``finish``),
    and nested ``children`` for its notes.
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    entries = document if isinstance(document, list) else [document]
    parsed: list[RawDiagnostic] = []
    for entry in entries:
        # GCC wraps each translation unit's diagnostics in its own array.
        if isinstance(entry, list):
            parsed.extend(_json_group(entry, tool_version))
        else:
            diagnostic = _json_diagnostic(entry, tool_version)
            if diagnostic is not None:
                parsed.append(diagnostic)
    return parsed


def _json_group(entries: Sequence[Any], tool_version: str) -> list[RawDiagnostic]:
    found = (_json_diagnostic(entry, tool_version) for entry in entries)
    return [diagnostic for diagnostic in found if diagnostic is not None]


def _json_diagnostic(entry: object, tool_version: str) -> RawDiagnostic | None:
    if not isinstance(entry, dict):
        return None
    location = _json_location(entry)
    if location is None:
        return None
    path, line, column, end_line = location
    severity = DiagnosticSeverity.parse(str(entry.get("kind") or "warning"))
    if severity is DiagnosticSeverity.NOTE:
        return None
    return RawDiagnostic(
        producer=Producer.CLANG_DIAGNOSTIC,
        tool_name=_TOOL_NAME,
        tool_version=tool_version,
        rule_id=str(entry.get("option") or ""),
        message=str(entry.get("message") or ""),
        path=path,
        line=line,
        column=column,
        end_line=end_line,
        severity=severity,
        notes=tuple(_json_notes(entry)),
        fix=_json_fix(entry),
    )


def _json_notes(entry: dict[str, Any]) -> list[RawNote]:
    notes: list[RawNote] = []
    for child in entry.get("children", []) if isinstance(entry.get("children"), list) else []:
        if not isinstance(child, dict):
            continue
        location = _json_location(child)
        if location is None:
            continue
        path, line, column, _end = location
        notes.append(
            RawNote(path=path, line=line, column=column, message=str(child.get("message") or ""))
        )
    return notes


def _json_fix(entry: dict[str, Any]) -> str | None:
    """Fix-it hints, as text. Recorded, never applied."""
    hints = entry.get("fixits")
    if not isinstance(hints, list):
        return None
    parts: list[str] = []
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        raw_start = hint.get("start")
        start: dict[str, Any] = raw_start if isinstance(raw_start, dict) else {}
        where = f"{start.get('file', '?')}:{start.get('line', '?')}"
        parts.append(f"{where} -> {str(hint.get('string', ''))!r}")
    return "; ".join(parts) or None


def _json_location(entry: dict[str, Any]) -> tuple[str, int, int, int | None] | None:
    """``(path, line, column, end_line)`` from a diagnostic's first location."""
    locations = entry.get("locations")
    if not isinstance(locations, list):
        return None
    for location in locations:
        if not isinstance(location, dict):
            continue
        anchor = location.get("caret") or location.get("start")
        if not isinstance(anchor, dict):
            continue
        path = str(anchor.get("file") or "")
        if not path:
            continue
        finish = location.get("finish")
        end_line = _int(finish.get("line"), default=0) or None if isinstance(finish, dict) else None
        return (
            path,
            _int(anchor.get("line"), default=1),
            _int(anchor.get("column"), default=0),
            end_line,
        )
    return None


def _int(value: object, *, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


# ------------------------------------------------------------------ analyzer


class DiagnosticsAnalyzer:
    """Runs the compiler for diagnostics only, and parses what it prints."""

    name = Producer.CLANG_DIAGNOSTIC
    tool_name = _TOOL_NAME

    def __init__(
        self,
        *,
        profile: CheckProfile,
        normalizer: Normalizer,
        clang: str = "clang",
        tool_version: str = "unknown",
        subprocess_runner: Subprocess | None = None,
    ) -> None:
        self._profile = profile
        self._normalizer = normalizer
        self._clang = clang
        self.tool_version = tool_version
        self._subprocess = subprocess_runner

    @property
    def output_format(self) -> str:
        return self._profile.diagnostic_format

    def command(self, unit: TranslationUnit) -> list[str]:
        """``-fsyntax-only``: diagnostics are wanted, object files are not."""
        format_flags = (
            ["-fdiagnostics-format=json"]
            if self.output_format == "json"
            else ["-fno-caret-diagnostics"]
        )
        return [
            self._clang,
            "-fsyntax-only",
            *format_flags,
            *analysis_flags(unit),
            *warnings_stay_warnings(),
            *self._profile.diagnostic_flags,
            source_argument(unit),
        ]

    def run(self, unit: TranslationUnit, timeout_s: float, *, out_dir: Path) -> AnalyzerRun:
        slug = str(unit.file).replace("/", "__")
        suffix = "json" if self.output_format == "json" else "txt"
        # Diagnostics arrive on stderr, so the console capture *is* the
        # artifact: one file, and the run still has a raw output to point at.
        output = out_dir / f"{slug}.diagnostics.{suffix}"
        return RunRequest(
            analyzer=self.name,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            profile_version=self._profile.version,
            unit=unit,
            command=self.command(unit),
            raw_output_path=output,
            log_path=output,
            subprocess_runner=self._subprocess,
        ).execute(timeout_s)

    def parse(self, run: AnalyzerRun) -> list[Candidate]:
        text = run.read_raw_output()
        if not text:
            return []
        parser = parse_json_diagnostics if self.output_format == "json" else parse_text_diagnostics
        diagnostics = [
            replace(item, unit=run.unit) for item in parser(text, tool_version=run.tool_version)
        ]
        return self._normalizer.to_candidates(
            sort_diagnostics(diagnostics), base=run.working_directory
        )
