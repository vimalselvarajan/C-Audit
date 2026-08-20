"""Part 09 variant tests: T-09-20.

Covers AC-09-1 from the other side. The flat-window control is the thing this
project argues against, and the argument is only worth anything if the control
is implemented honestly: a real line window, cutting a real function in half,
built by the same ``expand`` a scan calls rather than by a second code path
that exists to lose.

``needs_libclang`` for the same reason the rest of part 09's tests are — the
structural half of every comparison here is a question to the index.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caudit.model.finding import LimitationKind
from caudit.retrieval.policy import ExpansionPolicy, RetrievalVariant, UnitClass, UnitRole
from caudit.retrieval.service import expand
from tests.conftest import retrieval_candidate, retrieval_world

pytestmark = pytest.mark.needs_libclang


def _flat(lines: int = 40) -> ExpansionPolicy:
    return ExpansionPolicy(variant=RetrievalVariant.FLAT_WINDOW, flat_window_lines=lines)


# ------------------------------------------------------------------ T-09-20


def test_the_control_reads_a_window_and_clips_the_function_structural_returns_whole(
    tmp_path: Path,
) -> None:
    """T-09-20, AC-09-1: the difference the ablation is measuring, made visible.

    ``long_walk`` is 184 lines and the candidate sits ~80 lines into it. The
    structural variant returns the function with both boundaries exact; the
    control returns 20 lines either side and therefore holds neither end of
    it. If this test ever passes with the two producing the same region, the
    control has stopped being a control.
    """
    _root, index, store = retrieval_world(tmp_path, "expansion")
    symbol = index.symbols_named("long_walk")[0]
    assert symbol.definition is not None
    middle = symbol.definition.start_line + 80
    candidate = retrieval_candidate(store, "expansion.c", middle)

    structural = expand(candidate, index, store)
    control = expand(candidate, index, store, _flat(20))

    whole = structural.units_with_role(UnitRole.CONTAINING_FUNCTION)[0]
    assert whole.region.start_line == symbol.definition.start_line
    assert whole.region.end_line == symbol.definition.end_line

    window = control.units_with_role(UnitRole.FLAT_WINDOW)
    assert len(window) == 1
    assert window[0].region.start_line == middle - 20
    assert window[0].region.end_line == middle + 20
    # The clipping is the point: both ends of the function are outside it.
    assert window[0].region.start_line > symbol.definition.start_line
    assert window[0].region.end_line < symbol.definition.end_line


def test_the_control_retrieves_no_types_macros_callers_or_cleanup_paths(
    tmp_path: Path,
) -> None:
    """Everything structural retrieval exists to add is absent by design."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    symbol = index.symbols_named("long_walk")[0]
    assert symbol.definition is not None
    candidate = retrieval_candidate(store, "expansion.c", symbol.definition.start_line + 80)

    control = expand(candidate, index, store, _flat(20))
    roles = {unit.role for unit in control.units}

    assert UnitRole.FLAT_WINDOW in roles
    assert roles <= {UnitRole.FLAT_WINDOW, UnitRole.ANALYZER_MESSAGE}
    for absent in (
        UnitRole.CONTAINING_FUNCTION,
        UnitRole.TYPE_DECL,
        UnitRole.MACRO_DEF,
        UnitRole.CALLER,
        UnitRole.CALLEE,
        UnitRole.CLEANUP_PATH,
        UnitRole.GLOBAL_DECL,
    ):
        assert control.units_with_role(absent) == []


def test_the_control_says_in_the_context_that_it_is_a_window(tmp_path: Path) -> None:
    """A fragment and a whole function are indistinguishable in bytes.

    Part 11 judges a claim against what the model was shown, so the context
    states which kind of thing it is carrying rather than leaving a reader to
    infer it from a line count.
    """
    _root, index, store = retrieval_world(tmp_path, "expansion")
    symbol = index.symbols_named("long_walk")[0]
    assert symbol.definition is not None
    candidate = retrieval_candidate(store, "expansion.c", symbol.definition.start_line + 80)

    control = expand(candidate, index, store, _flat(20))
    said = [
        limitation
        for limitation in control.limitations
        if limitation.kind is LimitationKind.NO_EVIDENCE_EXPANSION
        and "flat_window" in limitation.detail
    ]

    assert len(said) == 1
    assert "ablation control" in said[0].detail
    assert "measurement configuration, not a scanning one" in said[0].detail


def test_the_window_is_a_primary_unit_the_budget_may_not_drop(tmp_path: Path) -> None:
    """A control whose only code unit could be dropped would measure nothing."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    symbol = index.symbols_named("long_walk")[0]
    assert symbol.definition is not None
    candidate = retrieval_candidate(store, "expansion.c", symbol.definition.start_line + 80)

    unit = expand(candidate, index, store, _flat(20)).units_with_role(UnitRole.FLAT_WINDOW)[0]

    assert unit.unit_class is UnitClass.PRIMARY
    assert unit.occurrences == 1
    assert unit.note is None


def test_the_window_is_clamped_to_the_file_rather_than_failing(tmp_path: Path) -> None:
    """A window wider than the file is the file, not an error."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    candidate = retrieval_candidate(store, "expansion.c", 3)

    unit = expand(candidate, index, store, _flat(1000)).units_with_role(UnitRole.FLAT_WINDOW)[0]

    assert unit.region.start_line == 1
    assert unit.region.end_line == store.line_count("expansion.c")


def test_the_control_still_carries_the_analyzers_own_message(tmp_path: Path) -> None:
    """The diagnostic arrives with the candidate; withholding it from one side
    would measure the diagnostic as well as the retrieval."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    candidate = retrieval_candidate(store, "expansion.c", 20)

    control = expand(candidate, index, store, _flat(5))

    assert control.units_with_role(UnitRole.ANALYZER_MESSAGE)


def test_the_control_is_reproducible(tmp_path: Path) -> None:
    """Two expansions of one candidate produce the same window and cost."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    candidate = retrieval_candidate(store, "expansion.c", 40)

    first = expand(candidate, index, store, _flat(15))
    second = expand(candidate, index, store, _flat(15))

    assert [unit.evidence_id for unit in first.units] == [unit.evidence_id for unit in second.units]
    assert first.total_tokens == second.total_tokens
