"""The Clang Static Analyzer: invocation and SARIF parsing.

Run as ``clang --analyze -Xclang -analyzer-output=sarif``, with every checker
named individually. Package-level enablement would be shorter, but `alpha.*`
checkers are experimental and noisy, and the profile exists so their
contribution to false positives can be tracked per rule and tuned with data.

Naming each checker has one consequence worth handling rather than
discovering: **an unknown checker id makes Clang refuse the whole
translation unit.** Checker sets move between LLVM releases —
``alpha.security.ArrayBoundV2`` exists in 18 and not in 20 — so a profile
pinned to one release would fail every unit on another. :func:`available_checkers`
asks the installed Clang what it has, once per run, and the ones it does not
recognise become a recorded limitation instead of a run-wide failure.

What this module preserves from the SARIF is the ``codeFlow``. A static
analyzer's value is the path it walked, and the order of that path *is* the
argument; the steps become ordered ``control_flow_step`` evidence and are
never re-sorted.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
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
    run_command,
    source_argument,
    warnings_stay_warnings,
)
from caudit.intake.plan import TranslationUnit
from caudit.model.candidate import Candidate
from caudit.model.evidence import EvidenceKind, Producer

__all__ = ["CsaAnalyzer", "available_checkers", "parse_sarif"]

_TOOL_NAME: Final = "clang-static-analyzer"

#: ``  core.NullDereference       Check for dereferences of null pointers``
_CHECKER_LINE: Final = re.compile(r"^\s{2,}([a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9_]+)+)\b")


def parse_sarif(text: str, *, tool_version: str) -> list[RawDiagnostic]:
    """Parse Clang's analyzer SARIF into raw diagnostics.

    Tolerant by design: a truncated or empty file yields no diagnostics rather
    than an exception, because the caller has already recorded *why* the run
    ended badly and a second failure would only bury it.
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(document, dict):
        return []

    diagnostics: list[RawDiagnostic] = []
    for run in _list(document.get("runs")):
        rules = _rule_table(run)
        for result in _list(run.get("results")):
            parsed = _result(result, rules, tool_version)
            if parsed is not None:
                diagnostics.append(parsed)
    return diagnostics


def _rule_table(run: Mapping[str, Any]) -> list[str]:
    """Rule ids in ``tool.driver.rules`` order, for ``ruleIndex`` lookups."""
    driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
    return [str(rule.get("id") or rule.get("name") or "") for rule in _list(driver.get("rules"))]


def _result(result: object, rules: Sequence[str], tool_version: str) -> RawDiagnostic | None:
    if not isinstance(result, dict):
        return None
    location = _first_location(_list(result.get("locations")))
    if location is None:
        return None
    path, line, column, end_line = location
    return RawDiagnostic(
        producer=Producer.CSA,
        tool_name=_TOOL_NAME,
        tool_version=tool_version,
        rule_id=_rule_id(result, rules),
        message=_text(result.get("message")),
        path=path,
        line=line,
        column=column,
        end_line=end_line,
        severity=DiagnosticSeverity.parse(str(result.get("level") or "warning")),
        flow=tuple(_code_flow(result)),
        notes=tuple(_related(result)),
    )


def _rule_id(result: Mapping[str, Any], rules: Sequence[str]) -> str:
    """``ruleId`` when present, else the entry ``ruleIndex`` points at."""
    rule_id = result.get("ruleId")
    if isinstance(rule_id, str) and rule_id:
        return rule_id
    index = result.get("ruleIndex")
    if isinstance(index, int) and 0 <= index < len(rules):
        return rules[index]
    return ""


def _code_flow(result: Mapping[str, Any]) -> list[RawNote]:
    """The analyzer's path, flattened in emission order.

    Every thread flow of every code flow, concatenated without sorting. SARIF
    allows a step to carry ``executionOrder``; Clang does not emit it, and
    inventing an order from indices we do not have would be worse than
    trusting the sequence the analyzer wrote.
    """
    steps: list[RawNote] = []
    for flow in _list(result.get("codeFlows")):
        for thread in _list(flow.get("threadFlows")):
            for entry in _list(thread.get("locations")):
                note = _flow_step(entry)
                if note is not None:
                    steps.append(note)
    return steps


def _flow_step(entry: object) -> RawNote | None:
    if not isinstance(entry, dict):
        return None
    location = entry.get("location")
    if not isinstance(location, dict):
        return None
    physical = _physical(location)
    if physical is None:
        return None
    path, line, column, end_line = physical
    return RawNote(
        path=path,
        line=line,
        column=column,
        end_line=end_line,
        message=_text(location.get("message")),
        kind=EvidenceKind.CONTROL_FLOW_STEP,
    )


def _related(result: Mapping[str, Any]) -> list[RawNote]:
    notes: list[RawNote] = []
    for entry in _list(result.get("relatedLocations")):
        if not isinstance(entry, dict):
            continue
        physical = _physical(entry)
        if physical is None:
            continue
        path, line, column, end_line = physical
        notes.append(
            RawNote(
                path=path,
                line=line,
                column=column,
                end_line=end_line,
                message=_text(entry.get("message")),
            )
        )
    return notes


def _first_location(locations: Sequence[Any]) -> tuple[str, int, int, int | None] | None:
    for entry in locations:
        physical = _physical(entry)
        if physical is not None:
            return physical
    return None


def _physical(entry: object) -> tuple[str, int, int, int | None] | None:
    """``(path, line, column, end_line)`` from a SARIF location."""
    if not isinstance(entry, dict):
        return None
    physical = entry.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or not uri:
        return None
    raw_region = physical.get("region")
    region: dict[str, Any] = raw_region if isinstance(raw_region, dict) else {}
    line = _int(region.get("startLine"), default=1)
    end_line = _int(region.get("endLine"), default=0) or None
    return _strip_scheme(uri), line, _int(region.get("startColumn"), default=0), end_line


def _strip_scheme(uri: str) -> str:
    """``file:///a/b.c`` → ``/a/b.c``. Anything else is returned unchanged."""
    return uri[len("file://") :] if uri.startswith("file://") else uri


def _text(message: object) -> str:
    if isinstance(message, dict):
        for key in ("text", "markdown"):
            value = message.get(key)
            if isinstance(value, str):
                return value
    return str(message) if isinstance(message, str) else ""


def _int(value: object, *, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


# --------------------------------------------------------------- capability


def available_checkers(
    clang: str, *, subprocess_runner: Subprocess | None = None, timeout_s: float = 60.0
) -> frozenset[str] | None:
    """Checker ids the installed Clang knows, or ``None`` if it would not say.

    ``None`` is not an empty set: it means the probe failed and the caller
    should use the profile unfiltered rather than concluding that Clang has no
    checkers. The difference is the same one this project draws everywhere
    between "nothing there" and "we could not look".
    """
    completed = run_command(
        [clang, "-cc1", "-analyzer-checker-help", "-analyzer-checker-help-alpha"],
        timeout_s=timeout_s,
        subprocess_runner=subprocess_runner,
    )
    if completed.status_is_failure and not completed.output.strip():
        return None
    found = {
        match.group(1)
        for match in (_CHECKER_LINE.match(line) for line in completed.output.splitlines())
        if match is not None
    }
    return frozenset(found) or None


# ------------------------------------------------------------------ analyzer


class CsaAnalyzer:
    """Runs ``clang --analyze`` over one translation unit and parses its SARIF."""

    name = Producer.CSA
    tool_name = _TOOL_NAME

    def __init__(
        self,
        *,
        profile: CheckProfile,
        normalizer: Normalizer,
        clang: str = "clang",
        tool_version: str = "unknown",
        checkers: Sequence[str] | None = None,
        subprocess_runner: Subprocess | None = None,
    ) -> None:
        self._profile = profile
        self._normalizer = normalizer
        self._clang = clang
        self.tool_version = tool_version
        self._checkers = tuple(checkers if checkers is not None else profile.csa_checkers())
        self._subprocess = subprocess_runner

    @property
    def checkers(self) -> tuple[str, ...]:
        return self._checkers

    def command(self, unit: TranslationUnit, output: Path) -> list[str]:
        """The exact argv. Recorded in the run, so a report can reproduce it."""
        selected = [
            argument
            for checker in self._checkers
            for argument in ("-Xclang", f"-analyzer-checker={checker}")
        ]
        return [
            self._clang,
            "--analyze",
            "-Xclang",
            "-analyzer-output=sarif",
            *selected,
            *analysis_flags(unit),
            *warnings_stay_warnings(),
            *self._profile.diagnostic_flags,
            "-o",
            str(output),
            source_argument(unit),
        ]

    def run(self, unit: TranslationUnit, timeout_s: float, *, out_dir: Path) -> AnalyzerRun:
        output = out_dir / f"{_slug(unit)}.csa.sarif"
        return RunRequest(
            analyzer=self.name,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            profile_version=self._profile.version,
            unit=unit,
            command=self.command(unit, output),
            raw_output_path=output,
            log_path=out_dir / f"{_slug(unit)}.csa.log",
            subprocess_runner=self._subprocess,
        ).execute(timeout_s)

    def parse(self, run: AnalyzerRun) -> list[Candidate]:
        text = run.read_raw_output()
        if not text:
            return []
        diagnostics = [
            replace(item, unit=run.unit)
            for item in parse_sarif(text, tool_version=run.tool_version)
        ]
        return self._normalizer.to_candidates(
            sort_diagnostics(diagnostics), base=run.working_directory
        )


def _slug(unit: TranslationUnit) -> str:
    """A filesystem-safe name for one unit's raw output."""
    return str(unit.file).replace("/", "__")
