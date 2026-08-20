"""Part 09 closure tests: T-09-01, T-09-02, T-09-03, T-09-07, T-09-09, T-09-18.

Covers AC-09-1, AC-09-2, AC-09-3, AC-09-7. Marked ``needs_libclang`` rather
than ``needs_clang``: retrieval is a set of questions to the part 06 index, and
that index is built through the wheel, which bundles its own shared library. A
retrieval test that stubbed the index would only be testing itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from caudit.evidence.store import SourceStore
from caudit.index import Index
from caudit.model.candidate import Candidate
from caudit.model.finding import LimitationKind
from caudit.retrieval.policy import DEFAULT_POLICY, ExpansionPolicy, UnitClass, UnitRole
from caudit.retrieval.service import expand, zoom
from tests.conftest import retrieval_candidate, retrieval_provenance, retrieval_world

pytestmark = pytest.mark.needs_libclang


# ---------------------------------------------------------------- T-09-01


def test_the_whole_containing_function_comes_back_with_exact_boundaries(
    tmp_path: Path,
) -> None:
    """T-09-01, AC-09-1: a candidate deep inside a long function.

    ``long_walk`` is 184 lines. The candidate sits roughly 80 lines into it,
    far enough from both ends that any window-based retrieval would clip one.
    """
    _root, index, store = retrieval_world(tmp_path, "expansion")
    symbol = index.symbols_named("long_walk")[0]
    assert symbol.definition is not None
    assert symbol.definition.line_count >= 180

    middle = symbol.definition.start_line + 80
    context = expand(retrieval_candidate(store, "expansion.c", middle), index, store)

    containing = context.units_with_role(UnitRole.CONTAINING_FUNCTION)
    assert len(containing) == 1
    unit = containing[0]
    assert unit.unit_class is UnitClass.PRIMARY
    # Both boundaries exact — the symbol's own extent, not a span around the
    # diagnostic.
    assert unit.region.start_line == symbol.definition.start_line
    assert unit.region.end_line == symbol.definition.end_line
    assert unit.region.sha256 == symbol.definition.sha256
    assert unit.symbol is not None
    assert unit.symbol.name == "long_walk"

    body = zoom(context, unit.evidence_id).decode("utf-8")
    assert body.startswith("u32 long_walk(")
    assert body.rstrip().endswith("}")


# ---------------------------------------------------------------- T-09-02


def test_the_closure_holds_the_typedef_the_struct_and_the_macro(tmp_path: Path) -> None:
    """T-09-02, AC-09-2: `struct hdr`, `typedef u32`, `#define MAX_SLOTS`."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(retrieval_candidate(store, "expansion.c", 120), index, store)

    named = {unit.symbol.name for unit in context.units if unit.symbol is not None}
    assert {"hdr", "u32"} <= named

    macros = [
        zoom(context, unit.evidence_id).decode("utf-8")
        for unit in context.units_with_role(UnitRole.MACRO_DEF)
    ]
    assert any("#define MAX_SLOTS 32" in text for text in macros)

    # All of it is primary: the closure is what makes the function readable,
    # so none of it may be dropped to save room.
    for role in (UnitRole.TYPE_DECL, UnitRole.MACRO_DEF):
        assert context.units_with_role(role)
        assert all(unit.unit_class is UnitClass.PRIMARY for unit in context.units_with_role(role))


# ---------------------------------------------------------------- T-09-07


def test_the_declarations_of_both_globals_the_function_touches_are_present(
    tmp_path: Path,
) -> None:
    """T-09-07, AC-09-2: `g_slots` is written, `g_flags` is read."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(retrieval_candidate(store, "expansion.c", 120), index, store)

    globals_present = {
        unit.symbol.name
        for unit in context.units_with_role(UnitRole.GLOBAL_DECL)
        if unit.symbol is not None
    }
    assert globals_present == {"g_slots", "g_flags"}

    declarations = [
        zoom(context, unit.evidence_id).decode("utf-8").strip()
        for unit in context.units_with_role(UnitRole.GLOBAL_DECL)
    ]
    assert "int g_slots;" in declarations
    assert "static u32 g_flags;" in declarations


def test_a_function_that_touches_no_global_gets_none(tmp_path: Path) -> None:
    """The graph is a fact about the code, not a list of every file-scope name."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(retrieval_candidate(store, "expansion.c", 258), index, store)

    assert context.units_with_role(UnitRole.CONTAINING_FUNCTION)
    assert context.units_with_role(UnitRole.GLOBAL_DECL) == []


# ---------------------------------------------------------------- T-09-03


def test_the_macro_that_hides_the_bounds_check_is_in_the_context(tmp_path: Path) -> None:
    """T-09-03, AC-09-3: the whole argument for closure over a line window."""
    _root, index, store = retrieval_world(tmp_path, "macro_bounds")
    context = expand(retrieval_candidate(store, "macro_bounds.c", 27), index, store)

    macros = {
        zoom(context, unit.evidence_id).decode("utf-8").strip()
        for unit in context.units_with_role(UnitRole.MACRO_DEF)
    }
    assert "#define CHECK_LEN(n) if ((n) >= 0 && (n) < BUF_LEN)" in macros
    # And transitively: CHECK_LEN reads as a bounds check only once the value
    # it bounds against is on the page too.
    assert "#define BUF_LEN 16" in macros


def test_the_closure_reaches_a_macro_used_only_inside_a_type(tmp_path: Path) -> None:
    """`BUF_LEN` sizes `struct Frame`, and is never written in the function."""
    root, index, store = retrieval_world(tmp_path, "macro_bounds")
    symbol = index.symbols_named("copy_into")[0]
    assert symbol.definition is not None

    body = (
        (root / "macro_bounds.c")
        .read_text(encoding="utf-8")
        .split("\n")[symbol.definition.start_line - 1 : symbol.definition.end_line]
    )
    assert "BUF_LEN" not in "\n".join(body)

    context = expand(retrieval_candidate(store, "macro_bounds.c", 27), index, store)
    assert any(
        b"#define BUF_LEN" in zoom(context, unit.evidence_id)
        for unit in context.units_with_role(UnitRole.MACRO_DEF)
    )


# ---------------------------------------------------------------- T-09-18


def test_a_path_crossing_three_functions_brings_all_three_back_whole(
    tmp_path: Path,
) -> None:
    """T-09-18, AC-09-1: the analyzer's path is the argument; no link is optional."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    # stage_one -> stage_two -> stage_three, reported as a control-flow path.
    candidate = retrieval_candidate(store, "expansion.c", 258, flow=(258, 253, 248))

    context = expand(candidate, index, store)

    primary_symbols = {
        unit.symbol.name
        for unit in context.primary_units
        if unit.symbol is not None
        and unit.role in (UnitRole.CONTAINING_FUNCTION, UnitRole.FLOW_FUNCTION)
    }
    assert primary_symbols == {"stage_one", "stage_two", "stage_three"}

    for name in ("stage_two", "stage_three"):
        symbol = index.symbols_named(name)[0]
        assert symbol.definition is not None
        unit = next(u for u in context.units if u.symbol is not None and u.symbol.name == name)
        assert unit.unit_class is UnitClass.PRIMARY
        assert (unit.region.start_line, unit.region.end_line) == (
            symbol.definition.start_line,
            symbol.definition.end_line,
        )


def test_a_function_already_retrieved_is_not_retrieved_twice(tmp_path: Path) -> None:
    """The path starts in the containing function; it is one region, once."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    candidate = retrieval_candidate(store, "expansion.c", 258, flow=(258, 258, 253))

    context = expand(candidate, index, store)

    ids = [unit.evidence_id for unit in context.units]
    assert len(ids) == len(set(ids))
    assert len(context.units_with_role(UnitRole.CONTAINING_FUNCTION)) == 1


# ---------------------------------------------------------------- T-09-09


@pytest.fixture(scope="module")
def expansion_world(tmp_path_factory: pytest.TempPathFactory) -> tuple[Index, SourceStore]:
    """One index, reused across every hypothesis example.

    Module-scoped on purpose: rebuilding it per example would make the
    property test a test of libclang's throughput.
    """
    _root, index, store = retrieval_world(tmp_path_factory.mktemp("property"), "expansion")
    return index, store


@given(budget=st.integers(min_value=500, max_value=50_000), line=st.integers(50, 200))
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_no_primary_unit_is_ever_a_subset_of_its_true_extent(
    expansion_world: tuple[Index, SourceStore], budget: int, line: int
) -> None:
    """T-09-09, AC-09-7: property-tested across randomized budgets.

    At every budget the run either emits nothing, or emits primaries at their
    full extent. There is no budget at which a function comes back shortened.
    """
    index, store = expansion_world
    candidate = retrieval_candidate(store, "expansion.c", line)

    context = expand(candidate, index, store, DEFAULT_POLICY, allowance=budget)

    assert context.total_tokens <= budget
    for unit in context.primary_units:
        if unit.symbol is None or unit.symbol.usr is None:
            continue
        symbol = index.symbol(unit.symbol.usr)
        assert symbol is not None
        extent = symbol.definition or symbol.declarations[0]
        assert (unit.region.start_line, unit.region.end_line) == (
            extent.start_line,
            extent.end_line,
        ), f"budget {budget} clipped {unit.symbol.name}"
        assert unit.region.byte_length == extent.byte_length


@given(budget=st.integers(min_value=1, max_value=400))
@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_a_budget_too_small_for_the_function_emits_nothing_at_all(
    expansion_world: tuple[Index, SourceStore], budget: int
) -> None:
    """AC-09-8: below the primary set's cost the answer is "not adjudicated"."""
    index, store = expansion_world
    candidate = retrieval_candidate(store, "expansion.c", 120)

    context = expand(candidate, index, store, DEFAULT_POLICY, allowance=budget)

    assert context.units == []
    assert context.total_tokens == 0
    assert not context.is_adjudicable
    assert context.review_reason is not None
    assert str(context.review_reason) == "context_budget_exceeded"
    # And the omission is still visible and still recoverable.
    assert context.dropped
    assert zoom(context, context.dropped[0].unit.evidence_id)


# ------------------------------------------------------------ closure gaps


def test_a_closure_the_index_could_not_complete_is_flagged(tmp_path: Path) -> None:
    """AC-09-2: a partial closure is never silently acceptable.

    The function is still readable; the header carrying its struct layout and
    the constant that sizes it is not. Coming back with the function and a
    confident silence about its type is exactly the failure the closure exists
    to prevent, so the gap is named.
    """
    root, index, store = retrieval_world(tmp_path, "closure_gap")
    candidate = retrieval_candidate(store, "closure_gap.c", 13)
    (root / "types.h").unlink()

    context = expand(candidate, index, store)

    assert context.units_with_role(UnitRole.CONTAINING_FUNCTION), "the function is still readable"
    assert context.units_with_role(UnitRole.TYPE_DECL) == []
    assert context.units_with_role(UnitRole.MACRO_DEF) == []

    incomplete = [
        limitation
        for limitation in context.limitations
        if limitation.kind is LimitationKind.NO_EVIDENCE_EXPANSION
        and "dependency closure" in limitation.detail
    ]
    assert incomplete, [limitation.detail for limitation in context.limitations]
    assert "slot_table" in incomplete[0].detail
    assert "cannot be read as absent" in incomplete[0].detail


def test_a_candidate_at_file_scope_gets_its_own_region_and_says_so(tmp_path: Path) -> None:
    """AC-09-1 has an honest failure mode, and this is it.

    A diagnostic outside any function has no containing function to retrieve.
    Handing back a span around the cited line under the ``containing_function``
    role would be a line window wearing AC-09-1's name, so the unit says what
    it is and the context records that nothing was expanded around it.
    """
    _root, index, store = retrieval_world(tmp_path, "expansion")
    # Line 26 is `int g_slots;` — file scope, no enclosing function.
    assert index.enclosing_function("expansion.c", 26) is None
    candidate = retrieval_candidate(store, "expansion.c", 26)

    context = expand(candidate, index, store)

    assert context.units_with_role(UnitRole.CONTAINING_FUNCTION) == []
    site = context.units_with_role(UnitRole.CANDIDATE_SITE)
    assert len(site) == 1
    assert site[0].unit_class is UnitClass.PRIMARY
    assert site[0].region.start_line == site[0].region.end_line == 26
    assert zoom(context, site[0].evidence_id).strip() == b"int g_slots;"

    # Nothing was expanded around it, and the report will say so.
    assert context.units_with_role(UnitRole.CALLER) == []
    assert context.units_with_role(UnitRole.TYPE_DECL) == []
    told = [
        limitation
        for limitation in context.limitations
        if limitation.kind is LimitationKind.NO_EVIDENCE_EXPANSION
        and "no function containing" in limitation.detail
    ]
    assert told
    assert "the cited region is all there is to read" in told[0].detail


def test_a_candidate_carrying_its_own_enclosing_region_is_retrieved_whole(
    tmp_path: Path,
) -> None:
    """The part 07 fallback: an analyzer recording that proved its own extent.

    The index cannot attribute the region to a function — the file was never
    parsed — but the candidate carries a region something else could prove, so
    it is retrieved whole rather than reduced to the diagnostic's line.
    """
    root, index, store = retrieval_world(tmp_path, "expansion")
    symbol = index.symbols_named("helper_one")[0]
    assert symbol.definition is not None

    unparsed = Index(revision=index.revision, repo_root=root, libclang=index.libclang)
    candidate = Candidate.create(
        region=store.make_region("expansion.c", 31, 31),
        message="a recording that declares its own containing function",
        provenance=retrieval_provenance(),
        suggested_cwe=["CWE-787"],
        enclosing_region=symbol.definition,
    )

    context = expand(candidate, unparsed, store)

    containing = context.units_with_role(UnitRole.CONTAINING_FUNCTION)
    assert len(containing) == 1
    assert containing[0].region == symbol.definition
    assert containing[0].symbol is None, "the index could not name it, so nothing claims to"
    assert any("no function containing" in limitation.detail for limitation in context.limitations)


def test_a_tree_that_changed_under_the_run_yields_no_units_at_all(tmp_path: Path) -> None:
    """Retrieval never invents bytes for a region it could not read.

    The candidate also carries a control-flow step, so the failure covers both
    what retrieval fetched and what the analyzer had already cited.
    """
    root, index, store = retrieval_world(tmp_path, "macro_bounds")
    candidate = retrieval_candidate(store, "macro_bounds.c", 27, flow=(25, 27))
    (root / "macro_bounds.c").unlink()

    context = expand(candidate, index, store)

    assert context.units == []
    assert LimitationKind.NO_EVIDENCE_EXPANSION in {
        limitation.kind for limitation in context.limitations
    }
    details = " ".join(limitation.detail for limitation in context.limitations)
    assert "could not be retrieved" in details
    assert "which could not be read at this revision" in details


def test_an_edit_that_keeps_the_offsets_valid_is_still_caught(tmp_path: Path) -> None:
    """A read that succeeds is not a read that is right.

    Prepending a line leaves every byte offset the index recorded inside the
    file, so the region still *reads*. It reads the wrong bytes. The hash is
    what notices, which is why every unit is re-checked against it rather than
    trusted because the read did not raise.
    """
    root, index, store = retrieval_world(tmp_path, "macro_bounds")
    candidate = retrieval_candidate(store, "macro_bounds.c", 27)
    source = root / "macro_bounds.c"
    source.write_text("/* prepended */\n" + source.read_text(encoding="utf-8"), encoding="utf-8")

    context = expand(candidate, index, store)

    assert context.units == []
    assert any(
        "the tree changed under this run" in limitation.detail for limitation in context.limitations
    )


def test_turning_the_closure_off_is_a_policy_choice_not_a_default(tmp_path: Path) -> None:
    _root, index, store = retrieval_world(tmp_path, "expansion")
    candidate = retrieval_candidate(store, "expansion.c", 120)

    without = expand(
        candidate, index, store, ExpansionPolicy(include_global_decls=False), allowance=50_000
    )
    assert without.units_with_role(UnitRole.GLOBAL_DECL) == []
    assert DEFAULT_POLICY.include_global_decls is True
