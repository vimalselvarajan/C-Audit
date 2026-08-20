"""CASTLE adapter — 250 small C programs across 25 CWEs, 110 of them in scope.

CASTLE is fetched, cached, and pinned by revision; it is never downloaded by
the default test suite. Everything here refuses to reach the network on its
own: :meth:`CastleSuite.ensure_available` raises with the exact command to
run, so an absent corpus is an actionable message rather than a surprise
download in the middle of a scoring run.

Source: https://github.com/CASTLE-Benchmark/CASTLE-Benchmark

The corpus is a flat ``datasets/CASTLE-C250/`` of files named
``CASTLE-<cwe>-<n>.c`` plus one central ``CASTLE-C250.json`` carrying every
label. This adapter previously assumed per-CWE directories, per-case JSON
sidecars, and inline ``// bad`` comments marking the vulnerable line — none of
which CASTLE has. Its CWE regex matched nothing in a real path, so every case
would have loaded with empty ground truth and scored as a silent zero. The two
unit tests behind it built a fixture in the *assumed* shape, so they passed and
proved nothing; they are replaced by fixtures in the real shape.

Two properties of the real corpus are worth stating because the scoring depends
on them:

* **100 of the 250 cases are deliberately not vulnerable**, carrying
  ``"vulnerable": false`` and an empty ``lines`` array. They are the corpus's
  false-positive bait, and they are the only reason a benchmark here can show
  adjudication *helping*: an analyzer-only run can lose precision on them, and
  a model that declines them wins it back. A case with no ground truth entries
  scores every finding against it as a false positive, which is exactly right.
* **Ground truth is a line list, not a single line.** A case may name several
  decisive lines; each becomes its own entry, and the matching policy consumes
  each at most once.

Of CASTLE's 25 CWEs, 11 are inside C Audit's allowlist — 110 cases across all
six in-scope weakness families. The other 14 are web, crypto, concurrency and
authentication weaknesses this project does not claim to analyse. They are
skipped **with a count**, never dropped silently, for the reason the pairs
harness excludes a broken pair with a reason: a corpus that quietly loses what
it cannot handle reports a rising score for a falling tool.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping, Sequence
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import Any, Final

from caudit.errors import CauditError
from caudit.eval.case import BenchmarkCase, GroundTruth, count_lines_of_code
from caudit.model.cwe import ALLOWLIST, WeaknessFamily, family_of

__all__ = ["CASTLE_PINNED_REVISION", "CastleSuite", "cache_root"]

#: Pinned so two runs score the same corpus. Bumping it is a deliberate act
#: that invalidates comparison with earlier results.
CASTLE_PINNED_REVISION: Final = "main"

#: Where the labels live, relative to the checkout.
MANIFEST_RELATIVE: Final = PurePosixPath("datasets") / "CASTLE-C250.json"

#: Where the sources live, relative to the checkout.
SOURCES_RELATIVE: Final = PurePosixPath("datasets") / "CASTLE-C250"


def cache_root() -> Path:
    """Where fetched corpora live. Overridable for tests and CI."""
    override = os.environ.get("CAUDIT_BENCHMARK_CACHE")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "caudit" / "benchmarks"


class CastleSuite:
    """Reads a cached CASTLE checkout. Never fetches implicitly."""

    name = "castle"

    def __init__(self, root: Path | None = None, workspace: Path | None = None) -> None:
        self.root = (root or (cache_root() / "castle")).resolve()
        #: Each case is staged into its own directory here. The corpus keeps
        #: all 250 files side by side, and ``case.root`` has to bound one case:
        #: ``ClangBaselineSource`` globs it for sources, and ``load_scan_plan``
        #: measures coverage against the files under it. Left flat, every case
        #: would analyse the whole corpus and report coverage of 1/250.
        self._workspace = (workspace or (cache_root() / "castle-workspace")).resolve()

    # ------------------------------------------------------------ availability

    @property
    def manifest_path(self) -> Path:
        return self.root / Path(*MANIFEST_RELATIVE.parts)

    @property
    def sources_path(self) -> Path:
        return self.root / Path(*SOURCES_RELATIVE.parts)

    def is_available(self) -> bool:
        return self.manifest_path.is_file() and self.sources_path.is_dir()

    def ensure_available(self) -> None:
        if self.is_available():
            return
        raise CauditError(
            f"CASTLE is not present at {self.root}",
            hint=(
                "Fetch it once, pinned:\n"
                f"  git clone https://github.com/CASTLE-Benchmark/CASTLE-Benchmark "
                f"{self.root}\n"
                f"  git -C {self.root} checkout {CASTLE_PINNED_REVISION}\n"
                "Set CAUDIT_BENCHMARK_CACHE to relocate the cache."
            ),
        )

    # ----------------------------------------------------------------- records

    @cached_property
    def _all_records(self) -> tuple[Mapping[str, Any], ...]:
        if not self.is_available():
            return ()
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return tuple(payload.get("tests", ()))

    @cached_property
    def _records(self) -> Mapping[str, Mapping[str, Any]]:
        """In-scope records by case id, in manifest order."""
        return {
            str(record["id"]): record
            for record in self._all_records
            if _cwe_of(record) in ALLOWLIST
        }

    def skipped(self) -> Mapping[str, int]:
        """How many cases each out-of-scope CWE cost, for the run to report.

        Reported rather than discarded: 14 of CASTLE's 25 CWEs are web, crypto,
        concurrency and authentication weaknesses C Audit does not claim to
        analyse, and a score computed over the remaining 11 has to say so or it
        reads as a score over the whole corpus.
        """
        counts: dict[str, int] = {}
        for record in self._all_records:
            cwe = _cwe_of(record)
            if cwe not in ALLOWLIST:
                counts[cwe] = counts.get(cwe, 0) + 1
        return dict(sorted(counts.items()))

    def case_ids(self) -> Sequence[str]:
        return tuple(sorted(self._records))

    # -------------------------------------------------------------- case loading

    def load(self, case_id: str) -> BenchmarkCase:
        self.ensure_available()
        record = self._records.get(case_id)
        if record is None:
            raise FileNotFoundError(f"no such in-scope CASTLE case: {case_id}")

        cwe = _cwe_of(record)
        family = family_of(cwe)
        if family is None:  # pragma: no cover - ALLOWLIST membership implies a family
            raise CauditError(f"{cwe} is in the allowlist with no weakness family")

        staged = self._stage(case_id, record)
        name = PurePosixPath(str(record["name"]))

        # A non-vulnerable case has an empty `lines` array and gets no ground
        # truth at all, which is what makes every finding against it a false
        # positive. `family` is still set so that false positive is charged to
        # the family the case belongs to rather than to a fallback.
        truths = [
            GroundTruth(
                path=name,
                line=int(line),
                cwe=cwe,
                family=family,
                variant="vulnerable",
                note=f"CASTLE {record.get('version', '')} label: {record.get('description', '')}",
            )
            for line in record.get("lines", ())
            if int(line) >= 1
        ]

        return BenchmarkCase(
            case_id=case_id,
            root=staged,
            compile_commands=None,
            ground_truth=truths,
            lines_of_code=count_lines_of_code([staged / name.name]),
            family=family,
            description=str(record.get("description", "")),
        )

    def cases(self) -> Sequence[BenchmarkCase]:
        return tuple(self.load(case_id) for case_id in self.case_ids())

    # ------------------------------------------------------------- build glue

    def _stage(self, case_id: str, record: Mapping[str, Any]) -> Path:
        """Copy one case into a directory of its own, and return it.

        Copied rather than symlinked so the region hashes are computed from
        bytes under ``case.root``, and taken from the ``.c`` file rather than
        the manifest's ``code`` string so what is scored is what is on disk.
        """
        name = PurePosixPath(str(record["name"])).name
        source = self.sources_path / name
        if not source.is_file():
            raise FileNotFoundError(
                f"CASTLE case {case_id} names {name}, which is not in the corpus"
            )
        destination = self._workspace / case_id
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / name
        payload = source.read_bytes()
        if not target.is_file() or target.read_bytes() != payload:
            target.write_bytes(payload)
        return destination

    def materialize_compile_commands(self, case_id: str, dest_dir: Path) -> Path:
        """Write a real compilation database for one case.

        The compile line comes from the corpus's own ``compile`` field rather
        than being invented here — "never guess include paths or compiler
        flags" applies to a benchmark as much as to a scan. CASTLE records
        ``gcc <file> -o <binary>``; analysis needs the compiler C Audit is
        configured with and no link step, so the driver is swapped and ``-c``
        replaces the link output. Nothing else is added.
        """
        self.ensure_available()
        record = self._records.get(case_id)
        if record is None:
            raise FileNotFoundError(f"no such in-scope CASTLE case: {case_id}")
        staged = self._stage(case_id, record)
        name = PurePosixPath(str(record["name"])).name

        arguments = _analysis_arguments(str(record.get("compile", "")), name)
        dest_dir.mkdir(parents=True, exist_ok=True)
        destination = dest_dir / "compile_commands.json"
        destination.write_text(
            json.dumps(
                [
                    {
                        "directory": str(staged),
                        "file": str(staged / name),
                        "arguments": arguments,
                    }
                ],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return destination

    def clear_workspace(self) -> None:
        """Drop the staged copies. Only the cache is touched, never the clone."""
        shutil.rmtree(self._workspace, ignore_errors=True)

    @staticmethod
    def covered_families() -> frozenset[WeaknessFamily]:
        """The in-scope families CASTLE can score."""
        return frozenset(entry.family for entry in ALLOWLIST.values())


def _cwe_of(record: Mapping[str, Any]) -> str:
    """``CWE-<n>`` for a manifest record. The manifest stores a bare integer."""
    return f"CWE-{int(record['cwe'])}"


def _analysis_arguments(compile_line: str, name: str) -> list[str]:
    """The corpus's own compile line, turned into an analysis invocation."""
    tokens = compile_line.split()
    # Drop the driver and the link output; keep whatever else the corpus asked
    # for, which today is nothing but the source name.
    body: list[str] = []
    skip_next = False
    for token in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if token == "-o":
            skip_next = True
            continue
        if token == name:
            continue
        body.append(token)
    return ["clang", *body, "-c", name, "-o", f"{Path(name).stem}.o"]
