"""Part 09 closure control test: T-09-04 (AC-09-3).

This is the control for T-09-03, and the only test in this part that asserts
something about a context that is *not* produced. It reads the fixture's bytes
directly rather than through the index, because the claim under test is about
what the code says, not about what retrieval does with it.

The recorded expectation: with the macro definition excluded, the remaining
evidence does not prove the bounds check exists. Every guard in `copy_into` is
spelled `CHECK_LEN(len)`, and `CHECK_LEN` could expand to a check, to nothing,
or to `if (1)`. A reader given only the function body cannot tell which — and
would be right to report an out-of-bounds write, because on the evidence in
front of them there is one.

That is why the closure in `retrieval.closure` is computed rather than sampled:
omitting it does not make the answer less precise, it makes it the opposite
answer.
"""

from __future__ import annotations

import re

from tests.conftest import FIXTURE_ROOT

_FIXTURE = FIXTURE_ROOT / "cpp" / "macro_bounds" / "macro_bounds.c"

#: `copy_into` in the committed fixture, located by name so the test does not
#: rot when a line moves above it.
_FUNCTION = re.compile(r"^void copy_into\(.*?^\}$", re.MULTILINE | re.DOTALL)


def _function_body() -> str:
    source = _FIXTURE.read_text(encoding="utf-8")
    match = _FUNCTION.search(source)
    assert match is not None, "copy_into is no longer in the fixture"
    return match.group(0)


def test_the_function_body_alone_states_no_bound() -> None:
    """T-09-04: the guard is a macro name, and a macro name proves nothing."""
    body = _function_body()

    # The copy is there, and it is bounded by `len`, which is a parameter.
    assert "frame->buf[index] = src[index];" in body
    assert "for (index = 0; index < len; index++)" in body

    # Nothing in the body says what bounds `len`, or what sizes `buf`.
    assert "BUF_LEN" not in body
    assert "16" not in body
    assert "CHECK_LEN(len)" in body


def test_the_bound_lives_entirely_outside_the_function() -> None:
    """Both halves of the check are elsewhere, in two different places."""
    source = _FIXTURE.read_text(encoding="utf-8")
    body = _function_body()
    outside = source.replace(body, "")

    assert "#define BUF_LEN 16" in outside
    assert "#define CHECK_LEN(n) if ((n) >= 0 && (n) < BUF_LEN)" in outside
    assert "char buf[BUF_LEN]" in outside


def test_a_context_without_the_macro_would_support_the_opposite_verdict() -> None:
    """The recorded expectation, stated as an assertion about the evidence.

    Given only the function, the strongest true statement is "an unbounded
    write into a fixed buffer". Given the macro too, the strongest true
    statement is "bounded, and correctly". One retrieval decision separates
    them, which is what makes a partial closure a correctness bug rather than
    a quality-of-context issue.
    """
    body = _function_body()
    macro = "#define CHECK_LEN(n) if ((n) >= 0 && (n) < BUF_LEN)"

    without_the_macro = body
    with_the_macro = f"{macro}\n{body}"

    # The predicate a reader applies: is there a comparison bounding the loop
    # variable against the buffer's size anywhere in what they were shown?
    def proves_a_bound(evidence: str) -> bool:
        return "BUF_LEN" in evidence and "<" in evidence

    assert not proves_a_bound(without_the_macro)
    assert proves_a_bound(with_the_macro)
