"""Part 07 dedup tests: T-07-11 … T-07-14, T-07-20 (AC-07-5, 6, 11).

The invariant under test is narrow and load-bearing: **merging never drops a
producer.** Provenance is what lets a reader tell "three analyzers agree" from
"one noisy check fired", and part 04 measures analyzer bias with it, so a
merge that quietly discarded an entry would corrupt both.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from caudit.analyzers.dedup import merge_candidates, sort_candidates
from caudit.model.candidate import Candidate
from caudit.model.evidence import Producer, Provenance
from caudit.model.source import SourceRegion, Symbol
from tests.conftest import make_region

_MESSAGE = "Call to function 'strcpy' is insecure"


def _provenance(
    producer: Producer = Producer.CSA,
    tool: str = "clang-static-analyzer",
    rule: str = "unix.Malloc",
    detail: str | None = None,
) -> Provenance:
    return Provenance(
        producer=producer,
        tool_name=tool,
        tool_version="18.1.8",
        rule_id=rule,
        detail=detail,
    )


def _candidate(
    *,
    line: int = 17,
    message: str = _MESSAGE,
    provenance: Provenance | None = None,
    cwe: tuple[str, ...] = ("CWE-787",),
    symbol: str | None = None,
    symbol_lines: tuple[int, int] = (15, 19),
    path: str = "src/main.c",
) -> Candidate:
    enclosing = (
        SourceRegion(
            path=PurePosixPath(path),
            start_line=symbol_lines[0],
            end_line=symbol_lines[1],
            start_byte=0,
            end_byte=64,
            sha256="b" * 64,
        )
        if symbol
        else None
    )
    return Candidate.create(
        region=make_region(path, line, line),
        message=message,
        provenance=[provenance or _provenance()],
        suggested_cwe=list(cwe),
        symbol=Symbol(name=symbol, kind="function", usr=f"c:{path}@F@{symbol}") if symbol else None,
        enclosing_region=enclosing,
    )


# ------------------------------------------------------------------ merging


def test_two_analyzers_on_one_defect_merge_into_one_candidate() -> None:
    """T-07-11: one candidate, two provenance entries, both rule ids kept."""
    csa = _candidate(provenance=_provenance(Producer.CSA, "clang-static-analyzer", "unix.Malloc"))
    tidy = _candidate(
        provenance=_provenance(
            Producer.CLANG_TIDY, "clang-tidy", "clang-analyzer-security.insecureAPI.strcpy"
        )
    )

    merged = merge_candidates([csa, tidy])

    assert len(merged) == 1
    assert len(merged[0].provenance) == 2
    assert {entry.rule_id for entry in merged[0].provenance} == {
        "unix.Malloc",
        "clang-analyzer-security.insecureAPI.strcpy",
    }
    assert {entry.tool_name for entry in merged[0].provenance} == {
        "clang-static-analyzer",
        "clang-tidy",
    }


def test_candidates_a_few_lines_apart_merge_with_a_deterministic_region() -> None:
    """T-07-13: the fingerprint ignores lines; the canonical region is fixed."""
    near = [_candidate(line=17), _candidate(line=19)]

    forwards = merge_candidates(near)
    backwards = merge_candidates(list(reversed(near)))

    assert len(forwards) == 1
    assert forwards[0].region.start_line == 17
    assert forwards[0].model_dump() == backwards[0].model_dump()


def test_the_same_message_in_two_functions_is_two_candidates() -> None:
    """T-07-14: the index's answer about *place* beats textual similarity."""
    first = _candidate(line=17, symbol="store_name", symbol_lines=(15, 19))
    second = _candidate(line=40, symbol="store_alias", symbol_lines=(38, 44))

    merged = merge_candidates([first, second])

    assert len(merged) == 2
    assert sorted(c.symbol.name for c in merged if c.symbol) == ["store_alias", "store_name"]


def test_one_function_reported_at_two_distant_lines_is_one_candidate() -> None:
    """A leak reported at the allocation and at the return is one leak."""
    first = _candidate(line=17, symbol="load_record", symbol_lines=(13, 60))
    second = _candidate(line=55, symbol="load_record", symbol_lines=(13, 60))

    assert len(merge_candidates([first, second])) == 1


def test_candidates_far_apart_with_no_index_do_not_merge() -> None:
    """Without a proven symbol, distance is all there is to go on."""
    assert len(merge_candidates([_candidate(line=17), _candidate(line=400)])) == 2


def test_different_files_never_merge() -> None:
    left = _candidate(path="src/main.c")
    right = _candidate(path="src/other.c")
    assert len(merge_candidates([left, right])) == 2


def test_merging_unions_the_suggested_cwes() -> None:
    """Disagreement between analyzers is a signal part 11 uses, not noise."""
    left = _candidate(cwe=("CWE-787",), provenance=_provenance(rule="a"))
    right = _candidate(cwe=("CWE-787", "CWE-125"), provenance=_provenance(rule="b"))

    merged = merge_candidates([left, right])
    assert merged[0].suggested_cwe == ["CWE-787", "CWE-125"]


def test_merging_keeps_each_analyzers_flow_intact() -> None:
    from caudit.model.evidence import EvidenceItem, EvidenceKind

    provenance = _provenance()
    steps = [
        EvidenceItem.create(
            kind=EvidenceKind.CONTROL_FLOW_STEP,
            # Distinct byte ranges: an evidence id is the content address of a
            # region, and three steps sharing one range are one citation.
            region=SourceRegion(
                path=PurePosixPath("src/main.c"),
                start_line=line,
                end_line=line,
                start_byte=line * 10,
                end_byte=line * 10 + 8,
                sha256=f"{line:064d}",
            ),
            provenance=[provenance],
        )
        for line in (3, 4, 5)
    ]
    # Lines chosen so the representative is fixed by the sort, not by a hash:
    # the earlier candidate leads, and the later one contributes what is new.
    left = _candidate(line=17, provenance=_provenance(rule="a")).model_copy(
        update={"evidence": steps[:2]}
    )
    right = _candidate(line=19, provenance=_provenance(rule="b")).model_copy(
        update={"evidence": steps[1:]}
    )

    merged = merge_candidates([left, right])
    assert [item.region.start_line for item in merged[0].evidence] == [3, 4, 5]


# ------------------------------------------------------- conservation (T-07-12)


_provenances = st.builds(
    _provenance,
    st.sampled_from(list(Producer)),
    st.sampled_from(["clang", "clang-tidy", "clang-static-analyzer"]),
    st.sampled_from(["unix.Malloc", "core.NullDereference", "-Wformat-security", ""]),
)

_candidates = st.builds(
    _candidate,
    line=st.integers(min_value=1, max_value=60),
    message=st.sampled_from([_MESSAGE, "Use of memory after it is freed", "leak of 8 bytes"]),
    provenance=_provenances,
    cwe=st.sampled_from([("CWE-787",), ("CWE-416",), ()]),
    symbol=st.sampled_from([None, "store_name", "touch_session"]),
    path=st.sampled_from(["src/main.c", "src/other.c"]),
)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_candidates, max_size=12))
def test_no_provenance_entry_is_lost_by_a_merge(candidates: list[Candidate]) -> None:
    """AC-07-6: whatever went in comes out, attached to something."""
    merged = merge_candidates(candidates)

    before = {entry for candidate in candidates for entry in candidate.provenance}
    after = {entry for candidate in merged for entry in candidate.provenance}
    assert before == after


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_candidates, max_size=12))
def test_every_input_provenance_lands_in_a_candidate_of_its_own_fingerprint(
    candidates: list[Candidate],
) -> None:
    """Conservation is per defect, not merely global."""
    merged = merge_candidates(candidates)

    before = {(c.fingerprint, entry) for c in candidates for entry in c.provenance}
    after = {(c.fingerprint, entry) for c in merged for entry in c.provenance}
    assert before == after


_distinguishable = st.builds(
    _candidate,
    line=st.integers(min_value=1, max_value=60),
    message=st.sampled_from([_MESSAGE, "Use of memory after it is freed", "leak of 8 bytes"]),
    provenance=st.builds(
        _provenance,
        st.sampled_from(list(Producer)),
        st.sampled_from(["clang", "clang-tidy", "clang-static-analyzer"]),
        st.sampled_from(["unix.Malloc", "core.NullDereference", "-Wformat-security"]),
        st.uuids().map(str),
    ),
    symbol=st.sampled_from([None, "store_name", "touch_session"]),
    path=st.sampled_from(["src/main.c", "src/other.c"]),
)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_distinguishable, max_size=12, unique_by=lambda c: c.provenance[0].detail))
def test_provenance_totals_are_conserved_across_a_merge(
    candidates: list[Candidate],
) -> None:
    """T-07-12: post-merge provenance count equals the pre-merge total.

    Every entry here is distinguishable — each carries its own detail — which
    is the case the invariant is really about. Merging is a *union*, so two
    byte-identical entries would legitimately collapse into the one entry they
    always were; nothing that could be told apart may disappear.
    """
    merged = merge_candidates(candidates)

    before = sum(len(candidate.provenance) for candidate in candidates)
    after = sum(len(candidate.provenance) for candidate in merged)
    assert after == before


# ------------------------------------------------------- determinism (T-07-20)


def test_shuffled_input_produces_an_identical_candidate_list() -> None:
    """AC-07-11: which translation unit finished first must not matter."""
    candidates = [
        _candidate(line=17, provenance=_provenance(rule="a")),
        _candidate(line=40, message="leak", provenance=_provenance(rule="b"), symbol="f"),
        _candidate(line=5, message="null deref", provenance=_provenance(rule="c")),
        _candidate(line=17, provenance=_provenance(rule="d")),
    ]
    orders = [
        candidates,
        list(reversed(candidates)),
        [candidates[2], candidates[0], candidates[3], candidates[1]],
    ]

    rendered = [[c.model_dump(mode="json") for c in merge_candidates(o)] for o in orders]
    assert rendered[0] == rendered[1] == rendered[2]


def test_sorting_is_a_total_order_over_path_then_position() -> None:
    unsorted = [
        _candidate(path="src/z.c", line=1),
        _candidate(path="src/a.c", line=9),
        _candidate(path="src/a.c", line=2),
    ]
    ordered = sort_candidates(unsorted)
    assert [(str(c.region.path), c.region.start_line) for c in ordered] == [
        ("src/a.c", 2),
        ("src/a.c", 9),
        ("src/z.c", 1),
    ]


def test_merging_an_empty_set_is_an_empty_list() -> None:
    assert merge_candidates([]) == []
