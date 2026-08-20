"""Juliet C/C++ 1.3 subset adapter.

Only the pinned CWE directories are wrapped — the full suite is 64,099 cases
and scoring all of it says more about throughput than about detection.

Juliet's value here is its **good/bad twins**: each test case contains a
flawed function and a fixed counterpart. The fixed twin is emitted as a
``variant="fixed"`` ground-truth entry, which turns a finding on it into a
false positive rather than a free pass. Without that pairing, precision on a
synthetic suite means very little.

Source: https://samate.nist.gov/SARD/test-suites/112
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Final

from caudit.errors import CauditError
from caudit.eval.adapters.castle import cache_root
from caudit.eval.case import BenchmarkCase, GroundTruth, count_lines_of_code
from caudit.model.cwe import WeaknessFamily, family_of

__all__ = ["JULIET_PINNED_CWES", "JulietSuite"]

#: One directory per in-scope family. Deliberately small and deliberately
#: named, so the corpus a score refers to is unambiguous.
JULIET_PINNED_CWES: Final[Mapping[str, WeaknessFamily]] = {
    "CWE-121": WeaknessFamily.OUT_OF_BOUNDS,
    "CWE-122": WeaknessFamily.OUT_OF_BOUNDS,
    "CWE-125": WeaknessFamily.OUT_OF_BOUNDS,
    "CWE-415": WeaknessFamily.MEMORY_LIFETIME,
    "CWE-416": WeaknessFamily.MEMORY_LIFETIME,
    "CWE-476": WeaknessFamily.NULL_UNINITIALIZED,
    "CWE-457": WeaknessFamily.NULL_UNINITIALIZED,
    "CWE-190": WeaknessFamily.INTEGER,
    "CWE-197": WeaknessFamily.INTEGER,
    "CWE-401": WeaknessFamily.RESOURCE_LEAK,
    "CWE-772": WeaknessFamily.RESOURCE_LEAK,
    "CWE-134": WeaknessFamily.INJECTION,
    "CWE-78": WeaknessFamily.INJECTION,
}

# Horizontal whitespace only: `\s` would let `^` match at the end of the
# previous line and report the function one line early.
_BAD_RE: Final = re.compile(r"^[ \t]*(?:static[ \t]+)?\w[\w \t*]*\bbad[ \t]*\(", re.MULTILINE)
_GOOD_RE: Final = re.compile(r"^[ \t]*(?:static[ \t]+)?\w[\w \t*]*\bgood\w*[ \t]*\(", re.MULTILINE)
_CWE_RE: Final = re.compile(r"CWE(\d{1,5})_")


class JulietSuite:
    """Reads a cached Juliet extraction, restricted to the pinned CWEs."""

    name = "juliet"

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or (cache_root() / "juliet")).resolve()

    def is_available(self) -> bool:
        return self.root.is_dir() and any(self.root.rglob("CWE*"))

    def ensure_available(self) -> None:
        if self.is_available():
            return
        raise CauditError(
            f"the Juliet subset is not present at {self.root}",
            hint=(
                "Download Juliet C/C++ 1.3 from "
                "https://samate.nist.gov/SARD/test-suites/112 and extract the "
                f"pinned CWE directories into {self.root}:\n  "
                + ", ".join(sorted(JULIET_PINNED_CWES))
                + "\nSet CAUDIT_BENCHMARK_CACHE to relocate the cache."
            ),
        )

    def _case_files(self) -> Sequence[Path]:
        if not self.root.is_dir():
            return ()
        return tuple(
            sorted(
                path
                for path in self.root.rglob("CWE*")
                if path.is_file()
                and path.suffix in {".c", ".cpp"}
                and self._cwe_for(path) in JULIET_PINNED_CWES
            )
        )

    def case_ids(self) -> Sequence[str]:
        return tuple(path.stem for path in self._case_files())

    @staticmethod
    def _cwe_for(path: Path) -> str | None:
        match = _CWE_RE.search(path.name)
        return f"CWE-{int(match.group(1))}" if match else None

    def load(self, case_id: str) -> BenchmarkCase:
        self.ensure_available()
        matches = [p for p in self._case_files() if p.stem == case_id]
        if not matches:
            raise FileNotFoundError(f"no such Juliet case: {case_id}")
        source = matches[0]
        cwe = self._cwe_for(source)
        if cwe is None:  # pragma: no cover - filtered by _case_files
            raise CauditError(f"cannot determine the CWE for {source}")
        family = JULIET_PINNED_CWES.get(cwe) or family_of(cwe)
        if family is None:  # pragma: no cover - pinned map covers every case
            raise CauditError(f"{cwe} is not an in-scope family")

        text = source.read_text(encoding="utf-8", errors="replace")
        relative = PurePosixPath(source.name)
        truths: list[GroundTruth] = []
        bad_line = self._first_match_line(text, _BAD_RE)
        if bad_line is not None:
            truths.append(
                GroundTruth(
                    path=relative,
                    line=bad_line,
                    cwe=cwe,
                    family=family,
                    variant="vulnerable",
                    note="Juliet bad() twin",
                )
            )
        good_line = self._first_match_line(text, _GOOD_RE)
        if good_line is not None:
            truths.append(
                GroundTruth(
                    path=relative,
                    line=good_line,
                    cwe=cwe,
                    family=family,
                    variant="fixed",
                    note="Juliet good() twin",
                )
            )
        return BenchmarkCase(
            case_id=case_id,
            root=source.parent,
            compile_commands=None,
            ground_truth=truths,
            lines_of_code=count_lines_of_code([source]),
            family=family,
            description=f"Juliet {cwe} case {case_id}",
        )

    def cases(self) -> Sequence[BenchmarkCase]:
        return tuple(self.load(case_id) for case_id in self.case_ids())

    @staticmethod
    def _first_match_line(text: str, pattern: re.Pattern[str]) -> int | None:
        match = pattern.search(text)
        if match is None:
            return None
        return text.count("\n", 0, match.start()) + 1
