"""Part 07 mini-suite tests: T-07-01 … T-07-06, T-07-18, T-07-21 (AC-07-1, 9).

Each in-scope weakness family gets one case. The recordings under
``tests/fixtures/analyzers/mini/`` are the analyzers' native output for those
cases, replayed through the real SARIF, YAML, and diagnostic parsers, so the
whole path from a tool's own bytes to a citable candidate runs offline.

Two cases deliberately have no recording. ``integer-truncation-alloc`` and
``resource-leak-error-path`` are flagged ``analyzer_blind_spot`` in the suite:
the facts that make them defects are split across translation units. The plan's
test table expects a candidate from every case; asserting one here would mean
either inventing analyzer output or quietly weakening the fixtures, so these
tests assert the blind spot instead — which is also the analyzer-bias
mitigation this part's risk section calls for. AC-07-1's other half, that the
profile can produce a candidate for every family, is checked in
``test_analyzer_profile.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.analyzers.csa import CsaAnalyzer
from caudit.analyzers.dedup import merge_candidates
from caudit.analyzers.diagnostics import DiagnosticsAnalyzer
from caudit.analyzers.normalize import Normalizer
from caudit.analyzers.profile import load_profile
from caudit.analyzers.runner import Analyzer
from caudit.analyzers.tidy import TidyAnalyzer
from caudit.eval.adapters.mini import MiniSuite
from caudit.eval.case import BenchmarkCase
from caudit.evidence.bundle import EvidenceBundle
from caudit.evidence.resolver import Citation, CitationResolver, ResolutionStatus
from caudit.evidence.store import SourceStore
from caudit.model.candidate import Candidate
from caudit.model.cwe import WeaknessFamily
from caudit.model.evidence import EvidenceKind, Producer
from tests.conftest import (
    analyzer_fixture,
    make_analyzer_run,
    make_translation_unit,
    materialize_recording,
)

#: Which recording stands in for each case, and which analyzer replays it.
RECORDINGS: dict[str, tuple[str, Producer]] = {
    "oob-write-stack-copy": ("tidy.template.yaml", Producer.CLANG_TIDY),
    "uaf-double-free": ("csa.sarif", Producer.CSA),
    "resource-leak-error-path": ("csa.sarif", Producer.CSA),
    "format-string-user-input": ("diagnostics.txt", Producer.CLANG_DIAGNOSTIC),
}

#: Cases the suite marks as analyzer blind spots, with why. Both were
#: *measured* on 2026-08-15 against clang 18.1.3, replacing two predictions
#: that turned out to be wrong in opposite directions — `resource-leak-error-
#: path` was predicted missed and is detected by `alpha.unix.Stream`, and
#: `null-deref-unchecked-alloc` was predicted detected and is not. See
#: benchmarks/mini/README.md.
BLIND_SPOTS = {
    "integer-truncation-alloc": "the truncation and the loop bound are in different TUs",
    "null-deref-unchecked-alloc": (
        "the analyzer does not split the state on allocation failure when nothing "
        "else in the function constrains the pointer"
    ),
}

#: How far a candidate may sit from the ground-truth line and still be that
#: defect. Analyzers report a path, not a point: a use-after-free can be
#: reported at the use or at the release.
LINE_TOLERANCE = 3


def _case(case_id: str) -> BenchmarkCase:
    return MiniSuite().load(case_id)


def _replay(case: BenchmarkCase, tmp_path: Path) -> list[Candidate]:
    """Run the recorded output for a case through the real parsers."""
    recording = RECORDINGS.get(case.case_id)
    if recording is None:
        return []
    name, producer = recording
    source = analyzer_fixture("mini", case.case_id, name)
    if name.endswith(".template.yaml"):
        artifact = materialize_recording(
            source, case.root, tmp_path / name.replace(".template", "")
        )
    else:
        artifact = source

    store = SourceStore(case.root, revision=f"fixture:{case.case_id}")
    normalizer = Normalizer(store=store, profile=load_profile(), index=None)
    unit = make_translation_unit(case.root, str(case.ground_truth[0].path))
    available: dict[Producer, Analyzer] = {
        Producer.CSA: CsaAnalyzer(profile=load_profile(), normalizer=normalizer),
        Producer.CLANG_TIDY: TidyAnalyzer(profile=load_profile(), normalizer=normalizer),
        Producer.CLANG_DIAGNOSTIC: DiagnosticsAnalyzer(
            profile=load_profile(), normalizer=normalizer
        ),
    }
    analyzer = available[producer]
    run = make_analyzer_run(
        unit=unit,
        raw_output_path=artifact,
        analyzer=producer,
        tool_name=analyzer.tool_name,
    )
    return merge_candidates(analyzer.parse(run))


# -------------------------------------------------- T-07-01 … T-07-06


@pytest.mark.parametrize("case_id", sorted(RECORDINGS))
def test_each_recorded_case_yields_a_candidate_at_its_ground_truth(
    case_id: str, tmp_path: Path
) -> None:
    """AC-07-1: one case per family, each producing at least one candidate."""
    case = _case(case_id)
    truth = case.vulnerable_truths[0]
    candidates = _replay(case, tmp_path)

    assert candidates, f"{case_id} produced no candidate"
    at_truth = [
        candidate
        for candidate in candidates
        if str(candidate.region.path) == str(truth.path)
        and abs(candidate.region.start_line - truth.line) <= LINE_TOLERANCE
    ]
    assert at_truth, (
        f"{case_id}: no candidate within {LINE_TOLERANCE} lines of "
        f"{truth.path}:{truth.line}; got "
        f"{[(str(c.region.path), c.region.start_line) for c in candidates]}"
    )


@pytest.mark.parametrize("case_id", sorted(RECORDINGS))
def test_each_recorded_case_maps_to_its_ground_truth_family(case_id: str, tmp_path: Path) -> None:
    """The profile's mapping has to agree with what the case is a case of."""
    case = _case(case_id)
    truth = case.vulnerable_truths[0]
    families = {family for c in _replay(case, tmp_path) for family in c.families}

    assert WeaknessFamily(truth.family) in families


def test_the_use_after_free_case_carries_static_analyzer_provenance(
    tmp_path: Path,
) -> None:
    """T-07-02: a CSA candidate, with the path it walked kept in order."""
    candidates = _replay(_case("uaf-double-free"), tmp_path)
    candidate = next(c for c in candidates if c.region.start_line == 24)

    assert [entry.producer for entry in candidate.provenance] == [Producer.CSA]
    assert candidate.provenance[0].rule_id == "unix.Malloc"
    assert candidate.suggested_cwe == ["CWE-401", "CWE-416", "CWE-415"]

    steps = [item for item in candidate.evidence if item.kind is EvidenceKind.CONTROL_FLOW_STEP]
    assert [item.region.start_line for item in steps] == [31, 38, 18, 24]


def test_the_format_string_case_comes_from_a_compile_diagnostic(tmp_path: Path) -> None:
    """The cheapest producer in the pipeline still names a whole family."""
    candidates = _replay(_case("format-string-user-input"), tmp_path)

    assert len(candidates) == 1
    assert candidates[0].provenance[0].producer is Producer.CLANG_DIAGNOSTIC
    assert candidates[0].provenance[0].rule_id == "-Wformat-security"
    assert candidates[0].suggested_cwe == ["CWE-134"]


def test_the_out_of_bounds_case_resolves_its_tidy_byte_offsets(tmp_path: Path) -> None:
    """clang-tidy addresses source by offset; the candidate addresses lines."""
    candidates = _replay(_case("oob-write-stack-copy"), tmp_path)

    assert len(candidates) == 1
    assert candidates[0].region.start_line == 17
    assert candidates[0].suggested_cwe == ["CWE-787"]
    # The note about the 16-byte destination is evidence, not a second candidate.
    assert [item.region.start_line for item in candidates[0].evidence] == [11]


# ------------------------------------------------------ T-07-04, T-07-05


@pytest.mark.parametrize("case_id", sorted(BLIND_SPOTS))
def test_a_flagged_blind_spot_still_produces_nothing(case_id: str, tmp_path: Path) -> None:
    """Deviation from the plan's test table, recorded rather than papered over.

    T-07-04 and T-07-05 ask for a candidate from the integer and resource-leak
    cases. Both are flagged ``analyzer_blind_spot``: the facts that make them
    defects live in different translation units, and no single-TU checker in
    the profile relates them. Claiming a candidate here would mean authoring
    analyzer output that no analyzer produces. The assertion is therefore the
    honest one — and it is the mitigation this part's risk section names, since
    a suite in which every case is found is evidence of fixtures written to
    match the tool.
    """
    case = _case(case_id)
    assert case.analyzer_blind_spot, f"{case_id} is no longer flagged; add its recording"
    assert _replay(case, tmp_path) == []


def test_the_suite_still_contains_cases_the_analyzers_miss() -> None:
    """A profile that found everything would be a profile fitted to fixtures."""
    blind = {case.case_id for case in MiniSuite().cases() if case.analyzer_blind_spot}
    assert blind == set(BLIND_SPOTS)


def test_every_mini_case_is_either_recorded_or_a_flagged_blind_spot() -> None:
    """No case may fall through the gap between the two lists."""
    assert set(MiniSuite().case_ids()) == set(RECORDINGS) | set(BLIND_SPOTS)


# ---------------------------------------------------------------- T-07-18


@pytest.mark.parametrize("case_id", sorted(RECORDINGS))
def test_every_candidate_region_resolves_through_part_three(case_id: str, tmp_path: Path) -> None:
    """AC-07-9: every citation this part emits holds when part 11 checks it."""
    case = _case(case_id)
    store = SourceStore(case.root, revision=f"fixture:{case.case_id}")
    resolver = CitationResolver(store, EvidenceBundle(store))

    candidates = _replay(case, tmp_path)
    assert candidates
    for candidate in candidates:
        for region in [candidate.region, *(item.region for item in candidate.evidence)]:
            resolution = resolver.resolve(Citation.from_region(region))
            assert resolution.status is ResolutionStatus.OK, resolution.detail


# ---------------------------------------------------------------- T-07-21


@pytest.mark.needs_clang
@pytest.mark.parametrize("case_id", sorted(MiniSuite().case_ids()))
def test_a_real_toolchain_produces_the_same_candidates_twice(case_id: str, tmp_path: Path) -> None:
    """T-07-21: two runs of the real analyzers agree, and record their versions.

    Deselected by default. This is the test that confirms the committed
    recordings: on a machine with Clang it exercises the same parsers against
    output the tools actually produced.
    """
    from caudit.analyzers.service import generate_candidates
    from caudit.config.loader import Config
    from caudit.index import build_index
    from caudit.intake import load_scan_plan

    suite = MiniSuite()
    database = suite.materialize_compile_commands(case_id, tmp_path / case_id)
    config = Config.model_validate({"intake": {"allow_partial_coverage": True}})
    plan = load_scan_plan(suite.root / case_id, database, config)
    index = build_index(plan, config, cache_dir=tmp_path / "index-cache")

    first = generate_candidates(plan, index, config, out_dir=tmp_path / "run-one")
    second = generate_candidates(plan, index, config, out_dir=tmp_path / "run-two")

    assert [c.model_dump(mode="json") for c in first.candidates] == [
        c.model_dump(mode="json") for c in second.candidates
    ]
    assert first.tool_versions
    for run in first.runs:
        assert run.tool_version and run.tool_version != "unknown"
        assert run.profile_version == "1"
