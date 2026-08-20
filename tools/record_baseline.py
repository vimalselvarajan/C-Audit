#!/usr/bin/env python3
"""Capture real analyzer output for the mini suite.

The committed ``baseline-candidates.json`` files start life as authored
expectations, because the machine this project was written on has no Clang.
This script replaces them with what the analyzers actually say, including
their real versions, and drops the ``needs_recapture`` flag.

Run it once on a machine with a supported toolchain:

    make record-baseline

It refuses to run without ``clang`` and ``clang-tidy`` rather than writing a
file that claims to be a capture and is not.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caudit.config.loader import Config
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.adjudicated import CompileCommandsFor
from caudit.eval.profiled import ProfiledCandidateSource
from caudit.evidence.store import SourceStore


def main() -> int:
    missing = [tool for tool in ("clang", "clang-tidy") if shutil.which(tool) is None]
    if missing:
        print(
            f"error: {', '.join(missing)} not found on PATH. "
            "See my_docs/guides/setup.md; refusing to write a recording that is not a capture.",
            file=sys.stderr,
        )
        return 3

    suite = MiniSuite()
    # The same pass `caudit scan` and `caudit eval --use-clang` run, under the
    # curated profile. It used to be `ClangBaselineSource`, whose ad-hoc check
    # list enables no compiler diagnostics and the whole `clang-analyzer-*`
    # glob -- so a recording made with it replayed a ruleset nobody ships, and
    # `--recorded` and `--use-clang` scored two different tools.
    with tempfile.TemporaryDirectory(prefix="caudit-record-") as scratch:
        workspace = Path(scratch)
        source = ProfiledCandidateSource(
            config=Config(),
            compile_commands=CompileCommandsFor(suite, workspace / "compile-commands"),
            out_dir=workspace / "analyzer-output",
        )
        code = _record_all(suite, source)
    return code


def _record_all(suite: MiniSuite, source: ProfiledCandidateSource) -> int:
    for case in suite.cases():
        store = SourceStore(case.root, revision=f"fixture:{case.case_id}")
        candidates = source.candidates_for(case, store)
        payload = {
            "source": "captured",
            "needs_recapture": False,
            "note": (
                "Captured from a real toolchain by tools/record_baseline.py. "
                "Regenerate after changing the fixture or the check profile."
            ),
            "diagnostics": [
                {
                    "path": str(candidate.region.path),
                    "line": candidate.region.start_line,
                    "end_line": candidate.region.end_line,
                    "message": candidate.message,
                    "rule_id": candidate.provenance[0].rule_id or "",
                    "tool_name": candidate.provenance[0].tool_name,
                    "tool_version": candidate.provenance[0].tool_version,
                    "producer": str(candidate.provenance[0].producer),
                    "cwe": list(candidate.suggested_cwe),
                    # Kept when the pass resolved it: without the containing
                    # function's span a replayed candidate cannot cite its own
                    # symbol, because nothing proves the line sits inside it.
                    **(
                        {
                            "symbol": candidate.symbol.name,
                            "symbol_start_line": candidate.enclosing_region.start_line,
                            "symbol_end_line": candidate.enclosing_region.end_line,
                        }
                        if candidate.symbol is not None and candidate.enclosing_region is not None
                        else {}
                    ),
                }
                for candidate in candidates
            ],
        }
        destination = case.root / "baseline-candidates.json"
        destination.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
        print(f"{case.case_id}: {len(candidates)} diagnostics -> {destination}")

    print(
        "\nReview the diff. If a case marked analyzer_blind_spot now has a "
        "diagnostic, drop the flag in case.json rather than leaving a stale claim."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
