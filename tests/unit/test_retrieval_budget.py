"""Part 09 budget tests: T-09-08, T-09-10, T-09-11, T-09-12, T-09-17.

Covers AC-09-6, AC-09-8, AC-09-9. The theme is that a budget decides what
appears on the page and never what a unit *is*: units are kept whole or
dropped whole, and when the whole primary set does not fit, the answer is
"this candidate was not adjudicated", not a smaller version of the question.
"""

from __future__ import annotations

import math

import pytest

from caudit.config.loader import TokenBudget
from caudit.model.finding import LimitationKind
from caudit.retrieval.budget import DEFAULT_TOKENIZER, HeuristicTokenizer, RunLedger, select
from caudit.retrieval.context import ContextUnit, DropReason
from caudit.retrieval.policy import UnitClass, UnitRole
from tests.conftest import FIXTURE_ROOT, make_context_unit

_MAX_UNITS = 64


def _primary(tokens: int, line: int = 10) -> ContextUnit:
    return make_context_unit(
        role=UnitRole.CONTAINING_FUNCTION, start_line=line, end_line=line + 5, token_estimate=tokens
    )


# ---------------------------------------------------------------- T-09-08


def test_the_selection_never_exceeds_the_budget() -> None:
    """T-09-08, AC-09-6: an oversized candidate set fits in 4000 tokens."""
    units = [
        make_context_unit(
            role=UnitRole.CONTAINING_FUNCTION, start_line=10, end_line=60, token_estimate=1200
        ),
        *(
            make_context_unit(
                role=UnitRole.CALLER,
                start_line=100 + step * 10,
                end_line=105 + step * 10,
                token_estimate=900,
                depth=1,
            )
            for step in range(10)
        ),
    ]

    selection = select(units, budget=4000, max_units=_MAX_UNITS)

    assert selection.total_tokens <= 4000
    assert selection.total_tokens == sum(unit.token_estimate for unit in selection.kept)
    # Three callers at 900 fit alongside the 1200-token primary; the rest do not.
    assert len(selection.kept) == 4
    assert len(selection.dropped) == 7


def test_an_empty_selection_is_free() -> None:
    selection = select([], budget=100, max_units=_MAX_UNITS)
    assert selection.total_tokens == 0
    assert selection.kept == ()
    assert not selection.primaries_exceed_budget


# ---------------------------------------------------------------- T-09-10


def test_primaries_that_do_not_fit_emit_no_context_at_all() -> None:
    """T-09-10, AC-09-8: 120% of the budget in primaries alone."""
    budget = 1000
    units = [
        make_context_unit(
            role=UnitRole.CONTAINING_FUNCTION, start_line=10, end_line=90, token_estimate=800
        ),
        make_context_unit(role=UnitRole.TYPE_DECL, start_line=4, end_line=8, token_estimate=400),
        make_context_unit(
            role=UnitRole.CALLER, start_line=200, end_line=210, token_estimate=50, depth=1
        ),
    ]

    selection = select(units, budget=budget, max_units=_MAX_UNITS)

    assert selection.primaries_exceed_budget
    assert selection.kept == ()
    assert selection.total_tokens == 0
    # Everything is recorded as dropped, including the supporting unit that
    # would have fitted: a context with supporting code and no function is not
    # a smaller context, it is a different one.
    assert len(selection.dropped) == 3
    assert {item.reason for item in selection.dropped} == {DropReason.PRIMARY_BUDGET_EXCEEDED}


def test_the_refusal_message_names_both_numbers() -> None:
    selection = select([_primary(1500)], budget=1000, max_units=_MAX_UNITS)
    detail = selection.dropped[0].detail
    assert "1500 tokens" in detail
    assert "budget of 1000" in detail


# ---------------------------------------------------------------- T-09-11


def test_supporting_units_are_dropped_whole_and_least_relevant_first() -> None:
    """T-09-11, AC-09-9: a budget that fits the primaries and half the rest."""
    primary = make_context_unit(
        role=UnitRole.CONTAINING_FUNCTION, start_line=10, end_line=40, token_estimate=100
    )
    supporting = [
        make_context_unit(
            role=UnitRole.CALLER, start_line=200, end_line=210, token_estimate=100, depth=1
        ),
        make_context_unit(
            role=UnitRole.CALLEE, start_line=300, end_line=310, token_estimate=100, depth=1
        ),
        make_context_unit(
            role=UnitRole.CALLER, start_line=400, end_line=410, token_estimate=100, depth=2
        ),
        make_context_unit(role=UnitRole.GLOBAL_DECL, start_line=5, end_line=5, token_estimate=100),
    ]
    ordered = [primary, *supporting]

    selection = select(ordered, budget=300, max_units=_MAX_UNITS)

    kept_roles = [unit.role for unit in selection.kept]
    assert kept_roles == [UnitRole.CONTAINING_FUNCTION, UnitRole.CALLER, UnitRole.CALLEE]
    # The two least relevant went: the depth-2 caller and the global.
    dropped = [item.unit for item in selection.dropped]
    assert [unit.role for unit in dropped] == [UnitRole.CALLER, UnitRole.GLOBAL_DECL]
    assert [unit.depth for unit in dropped] == [2, 0]
    # Whole, never partial: every dropped unit kept its full extent.
    for item in selection.dropped:
        assert item.unit.token_estimate == 100
        assert item.unit.region.line_count in {1, 11}


def test_max_units_caps_breadth_and_says_so() -> None:
    """A hot utility function with many callers is capped, not silently cut."""
    units = [
        make_context_unit(
            role=UnitRole.CONTAINING_FUNCTION, start_line=10, end_line=20, token_estimate=10
        ),
        *(
            make_context_unit(
                role=UnitRole.CALLER,
                start_line=100 + step,
                end_line=100 + step,
                token_estimate=1,
                depth=1,
            )
            for step in range(20)
        ),
    ]

    selection = select(units, budget=10_000, max_units=5)

    assert len(selection.kept) == 5
    assert {item.reason for item in selection.dropped} == {DropReason.MAX_UNITS}
    assert "configured cap" in selection.dropped[0].detail


def test_a_primary_is_never_counted_against_max_units() -> None:
    """The cap bounds breadth. Applying it to primaries would drop one."""
    units = [
        make_context_unit(
            role=UnitRole.CONTAINING_FUNCTION, start_line=10, end_line=20, token_estimate=10
        ),
        make_context_unit(role=UnitRole.TYPE_DECL, start_line=4, end_line=6, token_estimate=10),
        make_context_unit(role=UnitRole.MACRO_DEF, start_line=2, end_line=2, token_estimate=10),
    ]

    selection = select(units, budget=10_000, max_units=1)

    assert len(selection.kept) == 3
    assert selection.dropped == ()


# ---------------------------------------------------------------- T-09-12


def test_every_drop_becomes_a_limitation_naming_what_was_omitted() -> None:
    """T-09-12, AC-09-9: three drops, three limitations."""
    units = [
        make_context_unit(
            role=UnitRole.CONTAINING_FUNCTION, start_line=10, end_line=20, token_estimate=100
        ),
        *(
            make_context_unit(
                role=UnitRole.CALLER,
                start_line=200 + step * 10,
                end_line=205 + step * 10,
                token_estimate=100,
                depth=1,
            )
            for step in range(3)
        ),
    ]

    selection = select(units, budget=100, max_units=_MAX_UNITS)
    limitations = selection.limitations()

    assert len(selection.dropped) == 3
    assert len(limitations) == 3
    for limitation, item in zip(limitations, selection.dropped, strict=True):
        assert limitation.kind is LimitationKind.TOKEN_BUDGET_EXHAUSTED
        assert item.unit.region.describe() in limitation.detail
        assert "Any claim about this candidate was made without it" in limitation.detail
        assert limitation.affects == str(item.unit.region.path)


# ---------------------------------------------------------------- T-09-17
#
# The provider tokenizer does not exist yet — part 10 supplies it — so this is
# not a comparison against a guessed one. `HeuristicTokenizer` states an
# assumption about the family of tokenizers it will face ("tokens average at
# least `chars_per_token` characters") and these tests hold it to exactly that
# assumption, on committed C source rather than on invented strings.
#
# The never-under-count half is arithmetic and therefore total: if every token
# covers at least C characters, a text of length L cannot produce more than
# L/C tokens, which is at most `ceil(L/C)`, which is at most the estimate. The
# tolerance half bounds how far the newline surcharge may push it the other
# way, because an estimate that over-counts without limit is not a budget.

#: What the estimate must never fall below: the count of any tokenizer whose
#: tokens average at least this many characters.
_ASSUMED_RATIOS = (3.0, 3.5, 4.0, 6.0)

#: The documented tolerance. On real source the estimate may be at most this
#: many times a 3-chars-per-token count.
_TOLERANCE = 2.0


def _committed_source() -> list[str]:
    """The part 09 fixtures, which is what retrieval actually hands a model."""
    return [
        (FIXTURE_ROOT / "cpp" / name / f"{name}.c").read_text(encoding="utf-8")
        for name in ("macro_bounds", "expansion", "cleanup")
    ]


_SAMPLES = (
    *_committed_source(),
    "int f(void) { return 0; }\n",
    "static inline unsigned long compute_checksum_for_packet(const struct packet *p)\n",
    "    if ((length >= 0) && (length < MAX_BUFFER_LENGTH)) {\n        copy(dst, src);\n    }\n",
    "/* A comment that reads like ordinary English prose about the code. */\n",
    "a=b+c;d=e*f;g=h-i;j=k/l;\n" * 8,
)


@pytest.mark.parametrize("text", _SAMPLES, ids=range(len(_SAMPLES)))
@pytest.mark.parametrize("ratio", _ASSUMED_RATIOS)
def test_the_estimate_never_under_counts_a_conforming_tokenizer(text: str, ratio: float) -> None:
    """T-09-17, AC-09-6: over-counting is safe, under-counting overspends."""
    conforming = math.ceil(len(text) / ratio)
    assert DEFAULT_TOKENIZER.count(text) >= conforming


@pytest.mark.parametrize("text", _SAMPLES, ids=range(len(_SAMPLES)))
def test_the_estimate_stays_within_the_documented_tolerance(text: str) -> None:
    """T-09-17: bounded above, or the budget refuses candidates that fit."""
    tightest = math.ceil(len(text) / 3.0)
    assert DEFAULT_TOKENIZER.count(text) <= _TOLERANCE * tightest


@pytest.mark.parametrize("text", ["x" * 400, "\n\n\n\n\n", ""])
def test_degenerate_input_still_never_under_counts(text: str) -> None:
    """No tolerance is claimed here, only the direction that matters.

    A 400-character identifier and a run of blank lines are nothing like the
    source this will meet, and the estimate is wildly high on both. That costs
    a candidate some budget headroom; the opposite would cost it a truncated
    function.
    """
    assert DEFAULT_TOKENIZER.count(text) >= math.ceil(len(text) / 3.0)


def test_the_estimate_is_monotone_in_length() -> None:
    """Adding text never makes a context look cheaper."""
    short = DEFAULT_TOKENIZER.count("int x;\n")
    long = DEFAULT_TOKENIZER.count("int x;\nint y;\nint z;\n")
    assert long > short
    assert DEFAULT_TOKENIZER.count("") == 0


def test_the_ratio_is_configurable_for_a_hungrier_tokenizer() -> None:
    """Part 10 swaps this out; until then the knob is the safety margin."""
    conservative = HeuristicTokenizer(chars_per_token=2.0)
    text = "unsigned long value = compute(a, b);\n"
    assert conservative.count(text) > DEFAULT_TOKENIZER.count(text)
    assert conservative.count(text) == math.ceil(len(text) / 2.0) + 1


# ------------------------------------------------------------- run ledger


def test_the_run_ledger_hands_out_the_smaller_of_the_two_budgets() -> None:
    ledger = RunLedger(budget=TokenBudget(per_candidate=1000, per_run=2500))

    assert ledger.allowance() == 1000
    ledger.charge(2000)
    assert ledger.allowance() == 500
    ledger.charge(500)
    assert ledger.exhausted
    assert ledger.allowance() == 0


def test_a_starved_candidate_is_recorded_rather_than_shrunk() -> None:
    """Squeezing more candidates through by giving each less code is the
    failure this exists to prevent."""
    ledger = RunLedger(budget=TokenBudget(per_candidate=1000, per_run=1000))
    ledger.charge(1000)

    limitation = ledger.starve("cand-123")

    assert ledger.starved == ["cand-123"]
    assert limitation.kind is LimitationKind.TOKEN_BUDGET_EXHAUSTED
    assert limitation.affects == "cand-123"
    assert "nothing in this report is a statement about it" in limitation.detail
    assert "1 unexpanded" in ledger.describe()


def test_selection_classes_are_what_they_claim() -> None:
    """A guard on the fixture itself: the drop tests mean nothing if the
    helper silently builds everything as PRIMARY."""
    assert make_context_unit(role=UnitRole.CALLER).unit_class is UnitClass.SUPPORTING
    assert make_context_unit(role=UnitRole.TYPE_DECL).unit_class is UnitClass.PRIMARY
    assert (
        make_context_unit(role=UnitRole.ANALYZER_MESSAGE, note="x").unit_class
        is UnitClass.SECONDARY
    )
