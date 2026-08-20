"""The analyzer-only baseline: numbers with no AI in the pipeline.

The spec puts the harness at Milestone 0 so that later claims about Gemini
can be measured against something. This module produces that something.

Two candidate sources implement one protocol:

* :class:`ClangBaselineSource` shells out to ``clang-tidy`` and the Clang
  Static Analyzer. This is the thin direct invocation part 04 describes;
  part 07 replaces its internals with the shared normalizer and the
  interface stays put, so baseline numbers remain comparable across the
  swap. It requires a real toolchain.
* :class:`RecordedCandidateSource` replays analyzer output committed
  alongside a fixture. That is what keeps the default suite offline and
  runnable on a machine with no LLVM — including the current one.

Promotion from candidate to finding lives in :mod:`caudit.finding_policy.promotion` and
is re-exported here. Part 08 renders the same findings this harness scores,
so the two must come from one function: a report and a baseline that promoted
candidates differently would not be measuring the same tool.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Protocol

from caudit.errors import RegionError
from caudit.eval.case import BenchmarkCase
from caudit.evidence.store import SourceStore
from caudit.finding_policy.promotion import promote_candidate
from caudit.model.candidate import Candidate
from caudit.model.evidence import Producer, Provenance
from caudit.model.source import SourceRegion, Symbol

__all__ = [
    "CLANG_TIDY_CHECKS",
    "CandidateSource",
    "ClangBaselineSource",
    "RecordedCandidateSource",
    "promote_candidate",
]

#: The curated profile. Narrow on purpose: every enabled check must map to an
#: in-scope weakness family, or it only adds noise to FP/KLOC.
CLANG_TIDY_CHECKS: Final[tuple[str, ...]] = (
    "bugprone-*",
    "cert-*",
    "clang-analyzer-*",
    "-bugprone-easily-swappable-parameters",
    "-bugprone-narrowing-conversions",
    "-cert-dcl03-c",
    "-cert-err33-c",
)

#: ``path:line:col: severity: message [rule]``
_DIAG_RE: Final = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s+"
    r"(?P<severity>warning|error|note):\s+(?P<message>.*?)"
    r"(?:\s+\[(?P<rule>[\w.\-,]+)\])?$"
)

#: Analyzer rule id → CWE. Data, not inference: a check that has no accurate
#: mapping is left out rather than approximated.
RULE_CWE_MAP: Final[Mapping[str, tuple[str, ...]]] = {
    "clang-analyzer-core.NullDereference": ("CWE-476",),
    "clang-analyzer-core.CallAndMessage": ("CWE-476",),
    "clang-analyzer-core.uninitialized.Assign": ("CWE-457",),
    "clang-analyzer-core.uninitialized.Branch": ("CWE-457",),
    "clang-analyzer-core.UndefinedBinaryOperatorResult": ("CWE-457",),
    "clang-analyzer-unix.Malloc": ("CWE-401", "CWE-416", "CWE-415"),
    "clang-analyzer-unix.MallocSizeof": ("CWE-131",),
    "clang-analyzer-cplusplus.NewDelete": ("CWE-416", "CWE-415"),
    "clang-analyzer-cplusplus.NewDeleteLeaks": ("CWE-401",),
    "clang-analyzer-security.insecureAPI.strcpy": ("CWE-787",),
    "clang-analyzer-optin.taint.TaintedDiv": ("CWE-369",),
    "clang-analyzer-unix.cstring.OutOfBounds": ("CWE-787", "CWE-125"),
    "bugprone-use-after-move": ("CWE-416",),
    "bugprone-dangling-handle": ("CWE-416",),
    "bugprone-sizeof-expression": ("CWE-131",),
    "bugprone-misplaced-widening-cast": ("CWE-190",),
    "bugprone-integer-division": ("CWE-197",),
    "bugprone-signed-char-misuse": ("CWE-195",),
    "bugprone-too-small-loop-variable": ("CWE-190",),
    "cert-err33-c": ("CWE-252",),
    "cert-str34-c": ("CWE-195",),
    "clang-diagnostic-format-security": ("CWE-134",),
}


class CandidateSource(Protocol):
    """Anything that can produce candidates for a benchmark case."""

    name: str

    def candidates_for(self, case: BenchmarkCase, store: SourceStore) -> Sequence[Candidate]: ...

    def tool_versions(self) -> Mapping[str, str]: ...


# ---------------------------------------------------------------- recorded


@dataclass(frozen=True)
class RecordedDiagnostic:
    """One analyzer diagnostic, as committed next to a fixture."""

    path: str
    line: int
    end_line: int
    message: str
    rule_id: str
    tool_name: str
    tool_version: str
    producer: Producer
    cwe: tuple[str, ...]
    symbol: str | None = None
    #: Line span of the containing function. Without it the symbol claim
    #: cannot be cited, because nothing proves the line sits inside it.
    symbol_start_line: int | None = None
    symbol_end_line: int | None = None


class RecordedCandidateSource:
    """Replays analyzer output committed beside each fixture case.

    Regions are rebuilt from the fixture files on disk, so every hash in a
    replayed candidate is computed from real bytes. Nothing about the
    location is taken on trust from the recording.
    """

    name = "recorded"
    filename = "baseline-candidates.json"

    def __init__(self, filename: str | None = None) -> None:
        if filename is not None:
            self.filename = filename
        self._versions: dict[str, str] = {}

    def missing_recordings(self, cases: Iterable[BenchmarkCase]) -> list[str]:
        """Cases this source has nothing to replay for.

        ``candidates_for`` returns no candidates for such a case, which scores
        as a clean zero rather than as an error — correct for one case the
        analyzers genuinely had nothing to say about, and catastrophic for a
        whole suite that was never recorded, which would publish a corpus-wide
        zero as a measurement. Callers ask this *before* scoring so the
        difference is decided where it can still be refused.
        """
        return sorted(case.case_id for case in cases if not (case.root / self.filename).is_file())

    def candidates_for(self, case: BenchmarkCase, store: SourceStore) -> Sequence[Candidate]:
        recording = case.root / self.filename
        if not recording.is_file():
            return ()
        payload = json.loads(recording.read_text(encoding="utf-8"))
        candidates: list[Candidate] = []
        for entry in payload.get("diagnostics", []):
            diagnostic = RecordedDiagnostic(
                path=entry["path"],
                line=int(entry["line"]),
                end_line=int(entry.get("end_line", entry["line"])),
                message=entry["message"],
                rule_id=entry["rule_id"],
                tool_name=entry["tool_name"],
                tool_version=entry["tool_version"],
                producer=Producer(entry["producer"]),
                cwe=tuple(entry.get("cwe", ())),
                symbol=entry.get("symbol"),
                symbol_start_line=entry.get("symbol_start_line"),
                symbol_end_line=entry.get("symbol_end_line"),
            )
            self._versions[diagnostic.tool_name] = diagnostic.tool_version
            candidate = _candidate_from_diagnostic(diagnostic, store)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    def tool_versions(self) -> Mapping[str, str]:
        return dict(self._versions)


# ------------------------------------------------------------------- clang


class ClangBaselineSource:
    """Runs ``clang-tidy`` and the Clang Static Analyzer over a case.

    Requires a real toolchain; tests that use it carry ``needs_clang``.
    """

    name = "clang"

    def __init__(
        self,
        *,
        clang_tidy: str = "clang-tidy",
        clang: str = "clang",
        checks: Sequence[str] = CLANG_TIDY_CHECKS,
        timeout: int = 120,
    ) -> None:
        self.clang_tidy = clang_tidy
        self.clang = clang
        self.checks = tuple(checks)
        self.timeout = timeout
        self._versions: dict[str, str] = {}

    def candidates_for(self, case: BenchmarkCase, store: SourceStore) -> Sequence[Candidate]:
        sources = sorted(p for p in case.root.rglob("*.c") if p.is_file())
        sources += sorted(p for p in case.root.rglob("*.cpp") if p.is_file())
        candidates: list[Candidate] = []
        for source in sources:
            candidates.extend(self._run_clang_tidy(source, case, store))
            candidates.extend(self._run_analyzer(source, case, store))
        return _dedup(candidates)

    def tool_versions(self) -> Mapping[str, str]:
        return dict(self._versions)

    def _run_clang_tidy(
        self, source: Path, case: BenchmarkCase, store: SourceStore
    ) -> list[Candidate]:
        command = [
            self.clang_tidy,
            "--quiet",
            f"--checks=-*,{','.join(self.checks)}",
            str(source),
            "--",
            "-std=c11",
            f"-I{case.root}",
        ]
        output = self._run(command)
        self._versions.setdefault("clang-tidy", self._version_of(self.clang_tidy))
        return self._parse(
            output,
            case,
            store,
            Producer.CLANG_TIDY,
            "clang-tidy",
            self._versions["clang-tidy"],
        )

    def _run_analyzer(
        self, source: Path, case: BenchmarkCase, store: SourceStore
    ) -> list[Candidate]:
        command = [
            self.clang,
            "--analyze",
            "-Xclang",
            "-analyzer-output=text",
            "-std=c11",
            f"-I{case.root}",
            "-o",
            "/dev/null",
            str(source),
        ]
        output = self._run(command)
        self._versions.setdefault("clang-static-analyzer", self._version_of(self.clang))
        return self._parse(
            output,
            case,
            store,
            Producer.CSA,
            "clang-static-analyzer",
            self._versions["clang-static-analyzer"],
        )

    def _run(self, command: Sequence[str]) -> str:
        try:
            completed = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return f"{completed.stdout}\n{completed.stderr}"

    def _version_of(self, tool: str) -> str:
        from caudit.config.toolchain import parse_version

        try:
            completed = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):  # pragma: no cover
            return "unknown"
        return parse_version(f"{completed.stdout}\n{completed.stderr}") or "unknown"

    @staticmethod
    def _parse(
        output: str,
        case: BenchmarkCase,
        store: SourceStore,
        producer: Producer,
        tool_name: str,
        tool_version: str,
    ) -> list[Candidate]:
        candidates: list[Candidate] = []
        for raw in output.splitlines():
            match = _DIAG_RE.match(raw.strip())
            if match is None or match.group("severity") == "note":
                continue
            try:
                relative = Path(match.group("path")).resolve().relative_to(case.root.resolve())
            except ValueError:
                continue
            rule = match.group("rule") or ""
            diagnostic = RecordedDiagnostic(
                path=str(PurePosixPath(relative)),
                line=int(match.group("line")),
                end_line=int(match.group("line")),
                message=match.group("message").strip(),
                rule_id=rule,
                tool_name=tool_name,
                tool_version=tool_version,
                producer=producer,
                cwe=RULE_CWE_MAP.get(rule, ()),
            )
            candidate = _candidate_from_diagnostic(diagnostic, store)
            if candidate is not None:
                candidates.append(candidate)
        return candidates


def _dedup(candidates: Sequence[Candidate]) -> list[Candidate]:
    """Merge duplicates, preserving every provenance entry."""
    merged: dict[str, Candidate] = {}
    for candidate in candidates:
        existing = merged.get(candidate.fingerprint)
        merged[candidate.fingerprint] = (
            candidate if existing is None else existing.merged_with(candidate)
        )
    return list(merged.values())


def _candidate_from_diagnostic(
    diagnostic: RecordedDiagnostic, store: SourceStore
) -> Candidate | None:
    """Build a candidate whose region is verified against the real file."""
    try:
        region = store.make_region(diagnostic.path, diagnostic.line, diagnostic.end_line)
    except (RegionError, ValueError):
        return None
    provenance = Provenance(
        producer=diagnostic.producer,
        tool_name=diagnostic.tool_name,
        tool_version=diagnostic.tool_version,
        rule_id=diagnostic.rule_id or None,
        detail=None,
    )
    symbol = Symbol(name=diagnostic.symbol, kind="function") if diagnostic.symbol else None
    enclosing: SourceRegion | None = None
    if (
        symbol is not None
        and diagnostic.symbol_start_line is not None
        and diagnostic.symbol_end_line is not None
    ):
        try:
            enclosing = store.make_region(
                diagnostic.path, diagnostic.symbol_start_line, diagnostic.symbol_end_line
            )
        except (RegionError, ValueError):
            enclosing = None
    return Candidate.create(
        region=region,
        message=diagnostic.message,
        provenance=[provenance],
        suggested_cwe=list(diagnostic.cwe),
        symbol=symbol,
        enclosing_region=enclosing,
    )
