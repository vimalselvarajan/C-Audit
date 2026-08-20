"""Shared fixtures.

Nothing here opens a socket, shells out to a compiler, or reads the user's
real environment. Tests that need any of those carry a marker and are
deselected by default.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from caudit.analyzers.runner import AnalyzerRun, CommandResult, RunStatus, Subprocess
from caudit.config.loader import Config
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import CitationResolver
from caudit.evidence.store import SourceStore
from caudit.finding_policy.promotion import promote_candidate
from caudit.index import Index, build_index
from caudit.intake import load_scan_plan
from caudit.intake.plan import Coverage, TranslationUnit
from caudit.llm.service import (
    Cassette,
    CassetteProvider,
    ConsentDecision,
    ConsentSource,
    ProviderRequest,
    ProviderResponse,
    Usage,
)
from caudit.model.adjudication import Adjudication, Verdict
from caudit.model.candidate import Candidate
from caudit.model.evidence import EvidenceItem, EvidenceKind, Producer, Provenance
from caudit.model.finding import (
    Confidence,
    Exploitability,
    Finding,
    Impact,
    ImpactKind,
    MaintainabilityImpact,
    Reachability,
    Remediation,
    ReviewReason,
    Severity,
)
from caudit.model.ids import dedup_fingerprint, evidence_id, finding_id
from caudit.model.manifest import CoverageReport, RunManifest, ToolRecord
from caudit.model.source import SourceRegion, Symbol
from caudit.report.sections import ReportSections, build_sections
from caudit.retrieval.budget import DEFAULT_TOKENIZER
from caudit.retrieval.context import ContextUnit, EvidenceContext
from caudit.retrieval.policy import ExpansionPolicy, UnitRole, class_of, evidence_kind_of
from caudit.retrieval.policy import relevance as policy_relevance
from caudit.retrieval.service import expand

FIXTURE_ROOT = Path(__file__).parent / "fixtures"

#: Tools a `needs_clang` test cannot run without.
_CLANG_TOOLS = ("clang", "clang-tidy")


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip toolchain-dependent tests when the toolchain is not there.

    Two different dependencies, deliberately kept apart:

    * ``needs_clang`` wants ``clang`` and ``clang-tidy`` on PATH. It is
      deselected by default, so this only fires when someone asks for it.
    * ``needs_libclang`` wants only the ``libclang`` wheel, which is a hard
      dependency of the package and bundles its own shared library. Those tests
      run by default — indexing needs no system LLVM — and skip with a reason
      if the wheel cannot be loaded.
    """
    if item.get_closest_marker("needs_clang") is not None:
        missing = [tool for tool in _CLANG_TOOLS if shutil.which(tool) is None]
        if missing:
            pytest.skip(
                f"needs a Clang toolchain; missing {', '.join(missing)} (my_docs/guides/setup.md)"
            )
    if item.get_closest_marker("needs_libclang") is not None and not _libclang_loads():
        pytest.skip("the libclang wheel could not be loaded (pip install 'libclang>=18.1.1,<19')")


@cache
def _libclang_loads() -> bool:
    """Can libclang actually create an index? Asked once per session."""
    try:
        from clang import cindex

        cindex.Index.create()
    except Exception:
        return False
    return True


@pytest.fixture(autouse=True)
def _isolate_logging() -> Iterator[None]:
    """Keep handlers installed by one test out of the next one.

    ``propagate`` is saved with them, and that is not incidental:
    :func:`~caudit.logging.configure_logging` turns it off so a configured run
    logs once rather than twice, and any test that calls it would otherwise
    silence ``caplog`` for every later test in the session. A logging assertion
    that passes alone and fails in a full run is the worst kind of flake.
    """
    logger = logging.getLogger("caudit")
    saved_handlers = list(logger.handlers)
    saved_level = logger.level
    saved_propagate = logger.propagate
    yield
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    for handler in saved_handlers:
        logger.addHandler(handler)
    logger.setLevel(saved_level)
    logger.propagate = saved_propagate


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A tiny repository with one source file."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_bytes(
        b"#include <string.h>\n"
        b"\n"
        b"void copy_in(char *dst, const char *src)\n"
        b"{\n"
        b"    strcpy(dst, src);\n"
        b"}\n"
    )
    return tmp_path


@pytest.fixture
def store(repo: Path) -> SourceStore:
    return SourceStore(repo, revision="test-revision", max_file_bytes=1_000_000)


@pytest.fixture
def bundle(store: SourceStore) -> EvidenceBundle:
    return EvidenceBundle(store)


@pytest.fixture
def resolver(store: SourceStore, bundle: EvidenceBundle) -> CitationResolver:
    return CitationResolver(store, bundle)


@pytest.fixture
def provenance() -> list[Provenance]:
    return [
        Provenance(
            producer=Producer.CLANG_TIDY,
            tool_name="clang-tidy",
            tool_version="18.1.8",
            rule_id="clang-analyzer-security.insecureAPI.strcpy",
            detail=None,
        )
    ]


def make_region(
    path: str = "src/main.c",
    start_line: int = 5,
    end_line: int = 5,
    sha256: str | None = None,
) -> SourceRegion:
    """A syntactically valid region; the hash is arbitrary unless supplied."""
    return SourceRegion(
        path=PurePosixPath(path),
        start_line=start_line,
        end_line=end_line,
        start_byte=0,
        end_byte=32,
        sha256=sha256 or ("a" * 64),
    )


def make_evidence(
    provenance: list[Provenance],
    region: SourceRegion | None = None,
    kind: EvidenceKind = EvidenceKind.PRIMARY_CODE,
    symbol: Symbol | None = None,
) -> EvidenceItem:
    return EvidenceItem.create(
        kind=kind,
        region=region or make_region(),
        provenance=provenance,
        symbol=symbol,
    )


def make_finding(
    provenance: list[Provenance],
    *,
    cwe: str = "CWE-787",
    path: str = "src/main.c",
    start_line: int = 5,
    end_line: int | None = None,
    confidence: Confidence = Confidence.HIGH,
    confidence_reason: ReviewReason = ReviewReason.ALL_CITATIONS_RESOLVED,
    symbol: Symbol | None = None,
    message: str = "unbounded copy into a fixed buffer",
    region: SourceRegion | None = None,
) -> Finding:
    """A fully populated finding. Every contract field is filled."""
    location = region or make_region(path, start_line, end_line or start_line)
    symbol_name = symbol.name if symbol else None
    return Finding(
        finding_id=finding_id(
            cwe,
            location.path,
            symbol_name,
            message,
            start_byte=location.start_byte,
            end_byte=location.end_byte,
        ),
        fingerprint=dedup_fingerprint(cwe, location.path, symbol_name, message),
        cwe=cwe,
        cwe_rationale="Bounded by the destination's declared size; a write past it.",
        location=location,
        symbol=symbol,
        evidence=[make_evidence(provenance, location)],
        preconditions=["src is longer than the destination buffer"],
        impact=Impact(
            kind=ImpactKind.MEMORY_CORRUPTION,
            severity=Severity.HIGH,
            description="Adjacent stack memory is overwritten.",
            evidence_supports="The copy has no length bound at the cited line.",
        ),
        reachability=Reachability.UNKNOWN,
        exploitability=Exploitability.UNKNOWN,
        provenance=provenance,
        confidence=confidence,
        confidence_reason=confidence_reason,
        remediation=Remediation(
            strategy="Bound the copy to the destination's capacity.",
            rationale="The destination size is known at the call site.",
        ),
        maintainability_impact=MaintainabilityImpact(
            ownership="One caller; ownership is clear.",
            complexity="Single statement, no branching.",
            coupling="No callers outside this translation unit.",
            regression_risk="Low: the fix is local.",
            effort=Severity.LOW,
        ),
        limitations=[],
    )


# --------------------------------------------------------------- part 05


def write_tree(root: Path, files: Mapping[str, str]) -> Path:
    """Materialize ``{relative path: contents}`` under ``root``."""
    for relative, contents in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    return root


def compdb_entry(
    root: Path,
    file: str,
    *,
    directory: str | None = None,
    arguments: Sequence[str] | None = None,
    command: str | None = None,
    output: str | None = None,
) -> dict[str, Any]:
    """One database entry. Defaults to the ``arguments`` form with ``-c``."""
    working = directory if directory is not None else str(root / "build")
    entry: dict[str, Any] = {"directory": working, "file": file}
    if command is not None:
        entry["command"] = command
    else:
        absolute = file if Path(file).is_absolute() else str(root / file)
        entry["arguments"] = list(arguments) if arguments else ["clang", "-c", absolute]
    if output is not None:
        entry["output"] = output
    return entry


def write_compdb(
    root: Path, entries: Sequence[Mapping[str, Any]], *, name: str = "compile_commands.json"
) -> Path:
    """Write a compilation database into ``root/build`` and return its path."""
    build = root / "build"
    build.mkdir(parents=True, exist_ok=True)
    path = build / name
    path.write_text(json.dumps(list(entries), indent=2), encoding="utf-8")
    return path


def intake_config(**overrides: Any) -> Config:
    """A default :class:`Config` with ``intake.*`` keys overridden."""
    return Config.model_validate({"intake": overrides})


# --------------------------------------------------------------- part 06


def cpp_fixture(
    tmp_path: Path,
    name: str,
    *,
    language: str = "c",
    extra_arguments: Sequence[str] = (),
) -> tuple[Path, Path]:
    """Copy ``tests/fixtures/cpp/<name>`` into ``tmp_path`` with a database.

    Copied rather than used in place: index tests edit sources to exercise the
    incremental cache, and the compilation database has to carry absolute paths
    that only exist once the tree is somewhere real.
    """
    root = tmp_path / name
    shutil.copytree(FIXTURE_ROOT / "cpp" / name, root)
    sources = sorted(
        path for path in root.rglob("*") if path.is_file() and path.suffix in {".c", ".cc", ".cpp"}
    )
    standard = "-std=c++17" if language == "c++" else "-std=c11"
    entries = [
        {
            "directory": str(root),
            "file": str(source),
            "arguments": [
                "clang",
                standard,
                *extra_arguments,
                "-c",
                "-o",
                f"{source.stem}.o",
                str(source),
            ],
        }
        for source in sources
    ]
    database = root / "compile_commands.json"
    database.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return root, database


def index_config(**overrides: Any) -> Config:
    """A :class:`Config` whose ``index.*`` keys are overridden.

    Defaults to in-process parsing: the tests that matter are about what the
    index contains, and a worker process per unit would make them slower
    without making them stronger. The pool has its own tests.
    """
    settings: dict[str, Any] = {"in_process": True}
    settings.update(overrides)
    return Config.model_validate({"index": settings})


def make_candidate(
    provenance: list[Provenance],
    *,
    message: str = "unbounded copy",
    cwe: tuple[str, ...] = ("CWE-787",),
    region: SourceRegion | None = None,
) -> Candidate:
    return Candidate.create(
        region=region or make_region(),
        message=message,
        provenance=provenance,
        suggested_cwe=list(cwe),
    )


# --------------------------------------------------------------- part 07

ANALYZER_FIXTURES = FIXTURE_ROOT / "analyzers"

_OFFSET_PLACEHOLDER = re.compile(r"\$\{OFFSET:([^:}]+):(\d+)\}")


def analyzer_fixture(*parts: str) -> Path:
    """A committed analyzer recording, by path under ``fixtures/analyzers``."""
    return ANALYZER_FIXTURES.joinpath(*parts)


def materialize_recording(template: Path, root: Path, destination: Path) -> Path:
    """Resolve ``${OFFSET:path:line}`` placeholders against a real tree.

    ``clang-tidy --export-fixes`` addresses source by byte offset. A committed
    offset would be unwritable by hand and would rot the moment a line above it
    moved, so recordings carry the line they mean and the offset is computed
    here — the same reason ``compile_commands.template.json`` carries
    ``${CASE_ROOT}``.
    """
    store = SourceStore(root, revision="fixture")

    def resolve(match: re.Match[str]) -> str:
        start, _end = store.line_span_to_bytes(
            match.group(1), int(match.group(2)), int(match.group(2))
        )
        return str(start)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        _OFFSET_PLACEHOLDER.sub(resolve, template.read_text(encoding="utf-8")), encoding="utf-8"
    )
    return destination


def make_translation_unit(
    root: Path, relative: str = "src/main.c", *, arguments: Sequence[str] | None = None
) -> TranslationUnit:
    """One selected unit, spelled the way a compilation database would."""
    return TranslationUnit(
        file=relative,
        directory=root,
        arguments=list(arguments or ["clang", "-std=c11", "-Isrc", "-c", relative, "-o", "main.o"]),
        language="c",
    )


def make_analyzer_run(
    *,
    unit: TranslationUnit,
    raw_output_path: Path,
    analyzer: Producer = Producer.CSA,
    tool_name: str = "clang-static-analyzer",
    tool_version: str = "unrecorded",
    status: RunStatus = RunStatus.OK,
    exit_code: int = 0,
) -> AnalyzerRun:
    """An :class:`AnalyzerRun` pointing at a committed recording."""
    return AnalyzerRun(
        analyzer=analyzer,
        tool_name=tool_name,
        tool_version=tool_version,
        profile_version="1",
        unit=unit.file,
        working_directory=unit.directory,
        exit_code=exit_code,
        duration_s=0.0,
        status=status,
        command=["recorded"],
        raw_output_path=raw_output_path,
    )


def stub_subprocess(
    *,
    status: RunStatus = RunStatus.OK,
    exit_code: int = 0,
    output: str = "",
    writes: Mapping[str, str] | None = None,
    version_banner: str = "clang version 18.1.8",
) -> Subprocess:
    """A subprocess runner that never starts a process.

    ``writes`` maps a substring of the command line to the text the "tool"
    should leave in the file named by its ``-o``/``--export-fixes`` argument,
    so the whole run-then-parse path can be exercised offline.
    """

    def run(command: Sequence[str], _cwd: Path | None, _timeout: float) -> CommandResult:
        joined = " ".join(command)
        if "--version" in command:
            return CommandResult(RunStatus.OK, 0, version_banner, 0.0)
        for needle, text in (writes or {}).items():
            if needle in joined:
                target = _output_path(command)
                if target is not None:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(text, encoding="utf-8")
        return CommandResult(status, exit_code, output, 0.0)

    return run


def _output_path(command: Sequence[str]) -> Path | None:
    for index, argument in enumerate(command):
        if argument.startswith("--export-fixes="):
            return Path(argument.split("=", 1)[1])
        if argument == "-o" and index + 1 < len(command):
            return Path(command[index + 1])
    return None


# --------------------------------------------------------------- part 08

#: Fixed instants. The report tests assert byte-identical output, so the one
#: place a clock reading is allowed — the manifest — has to be pinned too.
REPORT_STARTED_AT = datetime(2026, 8, 12, 9, 0, tzinfo=UTC)
REPORT_FINISHED_AT = datetime(2026, 8, 12, 9, 4, 30, tzinfo=UTC)

#: A stand-in for a real configuration hash. The golden report quotes it, and
#: computing it from :class:`Config` would make the snapshot break every time
#: an unrelated configuration key was added.
REPORT_CONFIG_HASH = "ab" * 32

#: A small tree with one defect per file, written by :func:`write_demo_repo`.
#: Line numbers matter: :data:`DEMO_DIAGNOSTICS` cites them.
DEMO_TREE: Mapping[str, str] = {
    "src/alpha.c": (
        "#include <string.h>\n"
        "#include <stdlib.h>\n"
        "\n"
        "struct record {\n"
        "    char name[16];\n"
        "    int  size;\n"
        "};\n"
        "\n"
        "void copy_name(struct record *out, const char *src)\n"
        "{\n"
        "    /* No bound: src may be longer than name. */\n"
        "    strcpy(out->name, src);\n"
        "}\n"
        "\n"
        "int record_size(const struct record *record)\n"
        "{\n"
        "    return record->size;\n"
        "}\n"
    ),
    "src/beta.c": (
        "#include <stdlib.h>\n"
        "\n"
        "char *take(int count)\n"
        "{\n"
        "    char *buffer = malloc((size_t)count);\n"
        "    if (buffer == NULL) {\n"
        "        return NULL;\n"
        "    }\n"
        "    free(buffer);\n"
        "    return buffer;\n"
        "}\n"
        "\n"
        "void loop(unsigned short limit)\n"
        "{\n"
        "    for (unsigned short index = 0; index < limit * 2; index++) {\n"
        "        take(index);\n"
        "    }\n"
        "}\n"
    ),
    "src/gamma.c": (
        "#include <stdio.h>\n"
        "\n"
        "void report(const char *message)\n"
        "{\n"
        "    printf(message);\n"
        "}\n"
        "\n"
        "void trace(const char *label)\n"
        "{\n"
        "    fprintf(stderr, label);\n"
        "}\n"
    ),
}


@dataclass(frozen=True)
class DemoDiagnostic:
    """One analyzer diagnostic against :data:`DEMO_TREE`."""

    path: str
    line: int
    rule_id: str
    tool_name: str
    producer: Producer
    cwe: tuple[str, ...]
    message: str
    #: Lines of the analyzer's path, in the order it walked them.
    flow: tuple[int, ...] = ()


#: Six diagnostics: five that map to an in-scope family and one that maps to
#: nothing, so a fixture built from this always has both sections populated.
DEMO_DIAGNOSTICS: tuple[DemoDiagnostic, ...] = (
    DemoDiagnostic(
        path="src/alpha.c",
        line=12,
        rule_id="clang-analyzer-security.insecureAPI.strcpy",
        tool_name="clang-tidy",
        producer=Producer.CLANG_TIDY,
        cwe=("CWE-787",),
        message="Call to function 'strcpy' is insecure as it does not provide bounding",
    ),
    DemoDiagnostic(
        path="src/alpha.c",
        line=17,
        rule_id="core.NullDereference",
        tool_name="clang-static-analyzer",
        producer=Producer.CSA,
        cwe=("CWE-476",),
        message="Access to field 'size' results in a dereference of a null pointer",
    ),
    DemoDiagnostic(
        path="src/beta.c",
        line=10,
        rule_id="unix.Malloc",
        tool_name="clang-static-analyzer",
        producer=Producer.CSA,
        cwe=("CWE-401", "CWE-416", "CWE-415"),
        message="Use of memory after it is released",
        flow=(5, 6, 9, 10),
    ),
    DemoDiagnostic(
        path="src/beta.c",
        line=15,
        rule_id="bugprone-too-small-loop-variable",
        tool_name="clang-tidy",
        producer=Producer.CLANG_TIDY,
        cwe=("CWE-190",),
        message="Loop variable has narrower type than the bound it is compared against",
    ),
    DemoDiagnostic(
        path="src/gamma.c",
        line=5,
        rule_id="-Wformat-security",
        tool_name="clang",
        producer=Producer.CLANG_DIAGNOSTIC,
        cwe=("CWE-134",),
        message="format string is not a string literal (potentially insecure)",
    ),
    DemoDiagnostic(
        path="src/gamma.c",
        line=10,
        rule_id="caudit-demo-unmapped",
        tool_name="clang-tidy",
        producer=Producer.CLANG_TIDY,
        cwe=(),
        message="non-literal format string passed to fprintf",
    ),
)


def write_demo_repo(root: Path) -> Path:
    """Materialize :data:`DEMO_TREE` and an empty compilation database."""
    write_tree(root, dict(DEMO_TREE))
    (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    return root


def demo_candidates(
    store: SourceStore, diagnostics: Sequence[DemoDiagnostic] | None = None
) -> list[Candidate]:
    """Candidates whose regions are hashed from the real fixture bytes."""
    candidates: list[Candidate] = []
    for diagnostic in diagnostics if diagnostics is not None else DEMO_DIAGNOSTICS:
        provenance = [
            Provenance(
                producer=diagnostic.producer,
                tool_name=diagnostic.tool_name,
                tool_version="18.1.8",
                rule_id=diagnostic.rule_id,
            )
        ]
        evidence = [
            EvidenceItem.create(
                kind=EvidenceKind.CONTROL_FLOW_STEP,
                region=store.make_region(diagnostic.path, line, line),
                provenance=provenance,
            )
            for line in diagnostic.flow
        ]
        candidates.append(
            Candidate.create(
                region=store.make_region(diagnostic.path, diagnostic.line, diagnostic.line),
                message=diagnostic.message,
                provenance=provenance,
                suggested_cwe=list(diagnostic.cwe),
                evidence=evidence,
            )
        )
    return candidates


def demo_coverage(**overrides: Any) -> Coverage:
    base: dict[str, Any] = {
        "tus_in_database": 3,
        "tus_selected": 3,
        "source_files_in_tree": 3,
        "source_files_covered": 3,
        "coverage_ratio": 1.0,
    }
    base.update(overrides)
    return Coverage.model_validate(base)


def demo_sections(
    root: Path,
    *,
    diagnostics: Sequence[DemoDiagnostic] | None = None,
    coverage: Coverage | None = None,
    **kwargs: Any,
) -> ReportSections:
    """Promote the demo diagnostics and run the real evidence gate over them."""
    store = SourceStore(root, revision="demo-revision")
    findings = [
        promote_candidate(candidate, store=store)
        for candidate in demo_candidates(store, diagnostics)
    ]
    return build_sections(
        findings,
        resolver=CitationResolver(store, EvidenceBundle(store)),
        coverage=coverage or demo_coverage(),
        **kwargs,
    )


def demo_manifest(root: Path, sections: ReportSections, **overrides: Any) -> RunManifest:
    """A complete manifest with every varying value pinned.

    Built directly rather than through ``assemble_manifest`` so the golden
    report is a test of the renderer, not of whichever configuration keys
    happen to exist this month. ``assemble_manifest`` has its own tests.
    """
    base: dict[str, Any] = {
        "caudit_version": "0.1.0",
        "started_at": REPORT_STARTED_AT,
        "finished_at": REPORT_FINISHED_AT,
        "repository_root": str(root),
        "revision": "demo-revision",
        "revision_dirty": False,
        "compile_commands_path": str(root / "compile_commands.json"),
        "tools": [
            ToolRecord(name="clang", version="18.1.8", path="/usr/bin/clang"),
            ToolRecord(name="clang-static-analyzer", version="18.1.8"),
            ToolRecord(name="clang-tidy", version="18.1.8"),
            ToolRecord(name="libclang", version="18.1.1"),
        ],
        "config_hash": REPORT_CONFIG_HASH,
        "policy_versions": {"matching": "1", "profile": "1", "prompt": "1", "retrieval": "1"},
        "cited_region_hashes": sections.region_hashes(),
        "coverage": CoverageReport(
            translation_units_total=3,
            translation_units_parsed=3,
            translation_units_failed=0,
            lines_of_code=47,
            confirmed_count=sections.confirmed_count,
            review_required_count=sections.review_count,
        ),
    }
    base.update(overrides)
    return RunManifest.model_validate(base)


# --------------------------------------------------------------- part 09


def retrieval_world(tmp_path: Path, name: str) -> tuple[Path, Index, SourceStore]:
    """Copy a fixture tree, index it, and open a store over the same revision.

    Everything part 09 does is a question to the index, so a retrieval test
    that stubbed the index would only be testing itself.
    """
    root, database = cpp_fixture(tmp_path, name)
    config = index_config()
    plan = load_scan_plan(root, database, config, git_runner=lambda _args, _cwd: None)
    index = build_index(plan, config)
    return root, index, SourceStore(root, revision=index.revision)


def retrieval_provenance(rule: str = "unix.Malloc") -> list[Provenance]:
    return [
        Provenance(
            producer=Producer.CSA,
            tool_name="clang-static-analyzer",
            tool_version="18.1.8",
            rule_id=rule,
        )
    ]


def retrieval_candidate(
    store: SourceStore,
    path: str,
    line: int,
    *,
    message: str = "the value is used after it is released",
    cwe: Sequence[str] = ("CWE-416",),
    flow: Sequence[int] = (),
    provenance: list[Provenance] | None = None,
) -> Candidate:
    """A candidate whose regions are hashed from real fixture bytes."""
    entries = provenance or retrieval_provenance()
    steps = [
        EvidenceItem.create(
            kind=EvidenceKind.CONTROL_FLOW_STEP,
            region=store.make_region(path, step, step),
            provenance=entries,
        )
        for step in flow
    ]
    return Candidate.create(
        region=store.make_region(path, line, line),
        message=message,
        provenance=entries,
        suggested_cwe=list(cwe),
        evidence=steps,
    )


def retrieval_context(
    tmp_path: Path,
    name: str,
    path: str,
    line: int,
    *,
    config: Config | None = None,
    **candidate_kwargs: Any,
) -> EvidenceContext:
    """Index a fixture tree and expand one candidate in it, for real.

    Part 10's job is to render what part 09 assembled, so a stubbed context
    would test the renderer against a shape nothing produces.
    """
    _root, index, store = retrieval_world(tmp_path, name)
    candidate = retrieval_candidate(store, path, line, **candidate_kwargs)
    effective = config or Config()
    return expand(
        candidate,
        index,
        store,
        ExpansionPolicy.from_config(effective),
        effective.token_budget,
    )


def llm_config(**overrides: Any) -> Config:
    """A :class:`Config` whose ``llm.*`` keys are overridden.

    Triage is off by default here: most part 10 tests are about the
    adjudication tier, and a triage turn in front of every cassette would make
    each recording carry an exchange the test is not about.
    """
    settings: dict[str, Any] = {"triage_enabled": False, "cache_enabled": False}
    settings.update(overrides)
    return Config.model_validate({"llm": settings})


def granted_consent(detail: str = "consent granted for this test") -> ConsentDecision:
    return ConsentDecision(granted=True, source=ConsentSource.CONFIG, detail=detail)


CASSETTE_ROOT = Path(__file__).parent / "cassettes"

_EVIDENCE_PLACEHOLDER = re.compile(r"\$\{EVIDENCE_ID:(\d+)\}")


def load_cassette(name: str, *, evidence_ids: Sequence[str] = ()) -> Cassette:
    """A committed cassette, with its evidence-id placeholders resolved.

    An evidence id is a content address of real bytes, so a recording cannot
    hold one literally without pinning itself to a fixture's byte offsets —
    the same reason part 07's analyzer recordings carry ``${OFFSET:...}``
    rather than a number. ``${EVIDENCE_ID:0}`` means "the first id this
    candidate's context actually issued".
    """
    text = (CASSETTE_ROOT / f"{name}.json").read_text(encoding="utf-8")

    def resolve(match: re.Match[str]) -> str:
        index = int(match.group(1))
        if index >= len(evidence_ids):
            raise AssertionError(
                f"cassette '{name}' cites evidence id #{index}, but the context issued "
                f"only {len(evidence_ids)}"
            )
        return evidence_ids[index]

    return Cassette.model_validate_json(_EVIDENCE_PLACEHOLDER.sub(resolve, text))


def cassette_provider(
    name: str, *, evidence_ids: Sequence[str] = ()
) -> tuple[CassetteProvider, Cassette]:
    cassette = load_cassette(name, evidence_ids=evidence_ids)
    return CassetteProvider(cassette), cassette


class RefusingProvider:
    """A provider that fails the test if anything asks it a question.

    Stronger than asserting a call count afterwards: a call that should not
    have happened fails at the point it happens, with a stack that names it.
    """

    def __init__(self) -> None:
        self.requests: list[ProviderRequest] = []

    @property
    def calls(self) -> int:
        return len(self.requests)

    def adjudicate(self, request: ProviderRequest) -> ProviderResponse:
        self.requests.append(request)
        raise AssertionError("a request reached the provider, and none should have")

    def token_count(self, text: str) -> int:
        return DEFAULT_TOKENIZER.count(text)


def no_sleep(_seconds: float) -> None:
    """A backoff that records nothing and waits for nothing."""
    return None


class RecordingSleeper:
    """Captures the delays a retry loop would have waited."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


# --------------------------------------------------------------- part 11


#: The analyzer set a gate test is held to, matching what
#: :func:`retrieval_provenance` puts on its candidates. Named rather than
#: inlined so that a test about a *fabricated* analyzer has something real to
#: contrast with.
ANALYZERS_THAT_RAN = frozenset({"clang-static-analyzer"})


@dataclass(frozen=True)
class GateWorld:
    """One indexed fixture tree plus a context expanded inside it.

    Everything part 11 checks is a question to the index, the store, or the
    bundle, so a gate test that stubbed any of the three would be testing the
    stub. This carries all four objects :func:`~caudit.verify.gate.verify`
    takes, built the way a run builds them.
    """

    root: Path
    index: Index
    store: SourceStore
    context: EvidenceContext

    def evidence(self, position: int) -> str:
        return self.context.evidence_ids()[position]

    def ids_with_role(self, *roles: UnitRole) -> list[str]:
        """Issued ids whose units play one of ``roles``, in issue order.

        Fails loudly on an empty result: a test that filtered its way down to
        nothing and then asserted over the empty list would pass while checking
        nothing at all.
        """
        found = [
            identifier
            for identifier in self.context.evidence_ids()
            if (unit := self.context.unit(identifier)) is not None and unit.role in roles
        ]
        if not found:
            names = ", ".join(str(role) for role in roles)
            raise AssertionError(f"this context issued no {names} unit")
        return found


def gate_world(
    tmp_path: Path,
    name: str,
    path: str,
    line: int,
    *,
    config: Config | None = None,
    **candidate_kwargs: Any,
) -> GateWorld:
    """Index a fixture tree and expand one candidate in it, for real."""
    root, index, store = retrieval_world(tmp_path, name)
    candidate = retrieval_candidate(store, path, line, **candidate_kwargs)
    effective = config or Config()
    context = expand(
        candidate,
        index,
        store,
        ExpansionPolicy.from_config(effective),
        effective.token_budget,
    )
    return GateWorld(root=root, index=index, store=store, context=context)


def make_adjudication(context: EvidenceContext, **overrides: Any) -> Adjudication:
    """A proposal that passes every gate check, before a test breaks one thing.

    Defaults deliberately: ``confirmed``, citing the first two ids the context
    issued, claiming ``argued`` reachability and ``unknown`` exploitability —
    the strongest claim the citations alone support, so a test that changes one
    field is testing that field.
    """
    fields: dict[str, Any] = {
        "verdict": Verdict.CONFIRMED,
        "cited_evidence_ids": list(context.evidence_ids()[:2]),
        "cwe": "CWE-787",
        "cwe_rationale": (
            "The copy is bounded by the source length rather than the destination's declared size."
        ),
        "trigger_conditions": ["the supplied length exceeds the destination buffer"],
        "impact": Impact(
            kind=ImpactKind.MEMORY_CORRUPTION,
            severity=Severity.HIGH,
            description="Bytes past the end of the fixed buffer are overwritten.",
            evidence_supports="The cited copy has no bound derived from the destination.",
        ),
        "reachability": Reachability.ARGUED,
        "exploitability": Exploitability.UNKNOWN,
        "remediation": Remediation(
            strategy="Bound the copy to the destination's capacity.",
            rationale="The destination size is a compile-time constant here.",
        ),
        "maintainability_impact": MaintainabilityImpact(
            ownership="One caller in this translation unit.",
            complexity="A single statement changes.",
            coupling="No callers outside this file.",
            regression_risk="Low: the bound comes from the same declaration.",
        ),
        "unresolved_assumptions": ["the caller's length is attacker-influenced"],
        "confidence_self_report": Confidence.HIGH,
    }
    fields.update(overrides)
    return Adjudication(**fields)


# --------------------------------------------------------------- part 12


#: What the stubbed ``clang -fsyntax-only`` prints for :data:`DEMO_TREE`.
#: Enough to produce one candidate per file without pretending to be a real
#: compiler.
STUB_DIAGNOSTICS = (
    "src/alpha.c:12:5: warning: 'strcpy' is insecure [-Wdeprecated-declarations]\n"
    "src/gamma.c:5:12: warning: format string is not a string literal [-Wformat-security]\n"
)


@pytest.fixture
def clang_resource_dir() -> str:
    """Clang's builtin header directory, asked of Clang itself.

    ``index.resource_dir`` is configuration and C Audit deliberately never
    discovers it — that would be guessing an include path. A ``needs_clang``
    test is in the position of the user who supplies it: clang is on PATH, so
    ask it. Without one, a unit including ``<stddef.h>`` does not parse and the
    test would be measuring the wheel's missing headers instead of its subject.
    """
    result = subprocess.run(
        ["clang", "-print-resource-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("clang could not report its resource directory")
    return result.stdout.strip()


@pytest.fixture
def no_analyzers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every external analyzer binary un-findable, deterministically.

    The counterpart to :func:`stubbed_analyzers`, and the reason it exists is
    worth recording. Seven tests used to get this state from the machine —
    CLAUDE.md recorded that no Clang was installed here — and asserted
    ``ExitCode.ENVIRONMENT`` on that basis, several saying so in a comment.
    Installing ``clang-tidy`` turned all seven red at once without a line of
    production code changing, which is the signal that the environment was an
    input to the suite that nothing declared. None of those tests is *about*
    the toolchain: they check that the artifacts get written, that the plan is
    printed, that no socket is opened, that a flag is honoured. They need the
    no-analyzer branch held still, not discovered.

    ``shutil.which`` is wrapped rather than ``PATH`` emptied, because intake
    resolves the revision by running ``git``: a blank ``PATH`` would fail the
    run for an unrelated reason, and exit 3 would stop meaning what the
    assertion says it means. Both availability checks —
    ``analyzers.runner._run_subprocess`` and ``analyzers.tool_version`` — go
    through ``shutil.which``, so patching it covers both.
    """
    real_which = shutil.which

    def fake_which(
        cmd: str | os.PathLike[str],
        mode: int = os.F_OK | os.X_OK,
        path: str | os.PathLike[str] | None = None,
    ) -> str | None:
        # Matches the configured binaries (`clang`, `clang-tidy`) and the
        # version-suffixed spellings a distribution may install instead
        # (`clang-18`), without hiding `git`, `make` or anything else.
        name = Path(cmd).name
        if name.startswith("clang") or name == "scan-build":
            return None
        return real_which(cmd, mode, path)

    monkeypatch.setattr(shutil, "which", fake_which)


@pytest.fixture
def stubbed_analyzers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point candidate generation at a subprocess layer that runs nothing.

    ``build_analyzers`` is replaced rather than the analyzers themselves, so
    the real command lines, the real parsers, and the real normalizer all run;
    only the process launch is stubbed out.

    Lives here rather than in one test module because both part 08's and part
    12's end-to-end suites need it, and importing a fixture across test modules
    reads as a redefinition rather than as sharing.
    """
    from caudit.analyzers.normalize import Normalizer
    from caudit.analyzers.profile import load_profile
    from caudit.analyzers.runner import Analyzer
    from caudit.analyzers.service import build_analyzers
    from caudit.model.finding import Limitation

    runner = stub_subprocess(
        output=STUB_DIAGNOSTICS,
        writes={"--export-fixes": "Diagnostics: []\n", "--analyze": '{"runs": []}'},
    )

    def fake_build(
        *,
        profile: object = None,
        normalizer: Normalizer,
        config: Config,
        subprocess_runner: object = None,
    ) -> tuple[list[Analyzer], list[Limitation]]:
        return build_analyzers(
            profile=profile or load_profile(),  # type: ignore[arg-type]
            normalizer=normalizer,
            config=config,
            subprocess_runner=runner,
        )

    monkeypatch.setattr("caudit.analyzers.service.build_analyzers", fake_build)


def demo_project(tmp_path: Path) -> tuple[Path, Path]:
    """The demo tree with a database whose commands run at the repository root.

    The working directory matters: the stubbed compiler prints repository-
    relative paths, and part 07 resolves an analyzer's paths against the
    directory the build says the command runs in — never against ours.
    """
    root = write_tree(tmp_path / "demo", dict(DEMO_TREE))
    database = write_compdb(
        root,
        [
            compdb_entry(root, str(root / f"src/{name}.c"), directory=str(root))
            for name in ("alpha", "beta", "gamma")
        ],
    )
    return root, database


class ScriptedProvider:
    """A backend that answers every request from the ids the prompt issued.

    A cassette pins one recorded exchange to one candidate's evidence ids, which
    is right for part 10's tests and unusable for a whole-repository scan: each
    candidate gets its own context and its own ids, and a committed recording
    cannot know them.

    This is a *plumbing* double, deliberately not a model. It reads
    ``request.prompt.evidence_ids`` and returns a schema-valid answer citing the
    first of them, so the pipeline — expansion, the retry loop, validation, the
    gate, ranking, rendering — runs exactly as it would in production. What it
    cannot test is answer *quality*, and nothing here pretends otherwise: the
    measurement that needs a real model is ``caudit eval --no-baseline``.
    """

    def __init__(
        self,
        verdict: str = "confirmed",
        *,
        cwe: str = "CWE-787",
        fail_after: int | None = None,
    ) -> None:
        self.verdict = verdict
        self.cwe = cwe
        #: Raise :class:`ProviderUnavailableError` once this many requests have
        #: been answered, so a mid-run provider failure can be exercised.
        self.fail_after = fail_after
        self.requests: list[ProviderRequest] = []

    @property
    def calls(self) -> int:
        return len(self.requests)

    def adjudicate(self, request: ProviderRequest) -> ProviderResponse:
        from caudit.llm.service import ProviderUnavailableError

        self.requests.append(request)
        if self.fail_after is not None and len(self.requests) > self.fail_after:
            raise ProviderUnavailableError("the provider went away mid-run")
        return ProviderResponse(
            tier=request.tier,
            model_id=request.model_id,
            text=self._body(request),
            usage=Usage(input_tokens=1000, output_tokens=200),
            finish_reason="STOP",
        )

    def token_count(self, text: str) -> int:
        return DEFAULT_TOKENIZER.count(text)

    def _body(self, request: ProviderRequest) -> str:
        from caudit.llm.service import Tier

        if request.tier is Tier.TRIAGE:
            return json.dumps(
                {
                    "disposition": "adjudicate",
                    "ambiguous": False,
                    "impact": _SCRIPTED_IMPACT,
                    "rationale": "the scripted triage tier always escalates to adjudication",
                }
            )
        cited = list(request.prompt.evidence_ids[:1])
        return json.dumps(
            {
                "verdict": self.verdict,
                "cited_evidence_ids": cited,
                "cwe": self.cwe,
                "cwe_rationale": (
                    "The cited copy is bounded by the source length rather than the "
                    "destination's declared size."
                ),
                "trigger_conditions": ["the supplied length exceeds the destination buffer"],
                "impact": _SCRIPTED_IMPACT,
                "reachability": "argued",
                "exploitability": "unknown",
                "remediation": {
                    "strategy": "Bound the copy to the destination's capacity.",
                    "rationale": "The destination size is known at the cited site.",
                },
                "maintainability_impact": {
                    "ownership": "One caller in this translation unit.",
                    "complexity": "A single statement changes.",
                    "coupling": "No callers outside this file.",
                    "regression_risk": "Low: the bound comes from the same declaration.",
                    "effort": "low",
                },
                "unresolved_assumptions": ["the caller's length is attacker-influenced"],
                "confidence_self_report": "high",
                "quoted_evidence": [],
                "asserted_call_edges": [],
            }
        )


_SCRIPTED_IMPACT: Mapping[str, str] = {
    "kind": "memory_corruption",
    "severity": "high",
    "description": "Bytes past the end of the fixed buffer are overwritten.",
    "evidence_supports": "The cited copy has no bound derived from the destination.",
}


def make_context_unit(
    *,
    role: UnitRole = UnitRole.CONTAINING_FUNCTION,
    path: str = "src/main.c",
    start_line: int = 10,
    end_line: int = 20,
    token_estimate: int = 100,
    relevance: float | None = None,
    depth: int = 0,
    occurrences: int = 1,
    note: str | None = None,
    sha256: str | None = None,
) -> ContextUnit:
    """A unit with no filesystem behind it, for the pure-logic tests."""
    region = make_region(path, start_line, end_line, sha256=sha256 or f"{start_line:064d}")
    return ContextUnit(
        evidence_id=evidence_id(region, str(evidence_kind_of(role))),
        unit_class=class_of(role),
        role=role,
        region=region,
        relevance=policy_relevance(role, depth=depth) if relevance is None else relevance,
        token_estimate=token_estimate,
        depth=depth,
        occurrences=occurrences,
        note=note,
    )
