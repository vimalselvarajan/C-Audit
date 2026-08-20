"""Adapter for the committed ``benchmarks/mini/`` suite.

The mini suite is hand-written and lives in the repository so CI never
downloads anything: the default test suite is offline, and a machine with no
network and no LLVM can still run it.

Its weakness is structural and worth stating plainly — it was written by the
same project that is being measured, so it can encode the tool's blind spots.
Two cases are therefore marked ``analyzer_blind_spot``: they are known to be
missed by the deterministic analyzers, so a run where *everything* passes is
visibly suspicious rather than reassuring.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from caudit.eval.case import BenchmarkCase, GroundTruth, count_lines_of_code

__all__ = ["MINI_SUITE_ROOT", "MiniSuite"]

MINI_SUITE_ROOT: Final = Path(__file__).resolve().parents[4] / "benchmarks" / "mini"

_SOURCE_SUFFIXES: Final = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")


class MiniSuite:
    """Loads cases from a directory of ``<case_id>/case.json`` descriptors."""

    name = "mini"

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or MINI_SUITE_ROOT).resolve()

    def case_ids(self) -> Sequence[str]:
        if not self.root.is_dir():
            return ()
        return tuple(
            sorted(
                entry.name
                for entry in self.root.iterdir()
                if entry.is_dir() and (entry / "case.json").is_file()
            )
        )

    def load(self, case_id: str) -> BenchmarkCase:
        descriptor = self.root / case_id / "case.json"
        if not descriptor.is_file():
            raise FileNotFoundError(f"no such mini case: {case_id} ({descriptor})")
        raw: dict[str, Any] = json.loads(descriptor.read_text(encoding="utf-8"))
        case_root = descriptor.parent
        sources = sorted(
            path
            for path in case_root.rglob("*")
            if path.is_file() and path.suffix in _SOURCE_SUFFIXES
        )
        return BenchmarkCase(
            case_id=raw.get("case_id", case_id),
            root=case_root,
            compile_commands=None,
            ground_truth=[GroundTruth.model_validate(entry) for entry in raw["ground_truth"]],
            lines_of_code=count_lines_of_code(sources),
            family=raw.get("family"),
            analyzer_blind_spot=bool(raw.get("analyzer_blind_spot", False)),
            description=raw.get("description", ""),
        )

    def cases(self) -> Sequence[BenchmarkCase]:
        return tuple(self.load(case_id) for case_id in self.case_ids())

    # ------------------------------------------------------------ build glue

    def materialize_compile_commands(self, case_id: str, dest_dir: Path) -> Path:
        """Write a real compilation database for one case.

        Committed as a template with a ``${CASE_ROOT}`` placeholder because a
        compilation database contains absolute paths, and a committed
        absolute path would be wrong on every machine but one.
        """
        template_path = self.root / case_id / "compile_commands.template.json"
        if not template_path.is_file():
            raise FileNotFoundError(f"case {case_id} has no compile_commands.template.json")
        case_root = (self.root / case_id).resolve()
        text = template_path.read_text(encoding="utf-8").replace("${CASE_ROOT}", str(case_root))
        dest_dir.mkdir(parents=True, exist_ok=True)
        destination = dest_dir / "compile_commands.json"
        destination.write_text(text, encoding="utf-8")
        return destination


@lru_cache(maxsize=1)
def default_suite() -> MiniSuite:
    return MiniSuite()
