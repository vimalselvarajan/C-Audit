"""What gets pulled in, in what order, and how badly each piece is wanted.

Two orderings live here and they are not the same ordering.

**Class** decides what survives a binding budget. A ``PRIMARY`` unit is never
truncated and never dropped — if the primaries alone do not fit, the candidate
goes to review instead. A ``SUPPORTING`` unit is dropped whole. Only a
``SECONDARY`` unit may be compressed, and only by collapsing duplicates.

**Relevance** decides the order *within* a class, and it is a single number so
that the display order and the drop order cannot disagree: units are shown
most-relevant first and dropped least-relevant first, from one key. The spec
asks for dataflow proximity first, call-graph distance second, textual
proximity last; :func:`relevance` encodes exactly that, with the analyzer's own
reported path as the dataflow signal — it is the only dataflow evidence that
exists before part 10, and inventing a second one would be guessing.

The arithmetic is done in integer thousandths and divided once at the end.
Accumulating floats would make the ordering depend on the order the additions
happened in, and AC-09-12 says it must not.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from caudit.config.loader import Config
from caudit.model.evidence import EvidenceKind

__all__ = [
    "DEFAULT_POLICY",
    "ExpansionPolicy",
    "RetrievalVariant",
    "UnitClass",
    "UnitRole",
    "class_of",
    "evidence_kind_of",
    "relevance",
]


class RetrievalVariant(StrEnum):
    """How a candidate's context is gathered. Part 13's ablation axis.

    ``structural`` is what C Audit does and the only variant a scan should
    normally run: complete code units, chosen through the index.

    ``flat_window`` is the **control**, and it is deliberately the thing this
    project argues against — a fixed number of lines around the diagnostic,
    with no index consulted, which may well cut the containing function in
    half. It exists so the claim that compiler-aware retrieval earns its
    complexity can be measured rather than asserted. A context assembled this
    way always carries a limitation saying so, because a line window is not a
    code unit and nothing downstream should have to guess which it was handed.

    ``structural_plus_semantic`` is **not implemented**. Part 09 puts embedding
    and BM25 retrieval out of scope, and this enum names the variant so a grid
    can ask for it and be refused by name. Accepting it and running structural
    retrieval underneath would file structural numbers under a semantic label,
    which is the one outcome worse than not having the variant at all.
    """

    STRUCTURAL = "structural"
    STRUCTURAL_PLUS_SEMANTIC = "structural_plus_semantic"
    FLAT_WINDOW = "flat_window"


class UnitClass(StrEnum):
    """How a unit is allowed to be treated when the budget binds."""

    #: Never compressed, never truncated, never dropped.
    PRIMARY = "primary"
    #: Dropped whole if the budget binds. Never partially.
    SUPPORTING = "supporting"
    #: Compressible: duplicate diagnostics, logs, outlines. Never code.
    SECONDARY = "secondary"


class UnitRole(StrEnum):
    """Why a unit is in the context. Doubles as the expansion order."""

    #: The complete function containing the candidate.
    CONTAINING_FUNCTION = "containing_function"
    #: The cited region itself, used only when no containing function exists —
    #: a diagnostic at file scope, or in a unit that did not parse. It is never
    #: a window cut out of a function: when there is a function, the function
    #: is what gets retrieved.
    CANDIDATE_SITE = "candidate_site"
    #: A fixed line window around the diagnostic, produced only by the
    #: ``flat_window`` ablation control. It is the one role that may hold a
    #: fragment of a function, which is exactly what the control is measuring,
    #: and it is why it is a role of its own rather than a reused
    #: ``CANDIDATE_SITE``: a reader of a context must be able to tell a whole
    #: unit from a window without inspecting the bytes.
    FLAT_WINDOW = "flat_window"
    #: A complete function on the analyzer's reported source-to-sink path.
    FLOW_FUNCTION = "flow_function"
    #: A struct, union, enum, or typedef the primary function names.
    TYPE_DECL = "type_decl"
    #: A macro expanded inside the primary function.
    MACRO_DEF = "macro_def"
    #: A function that calls the primary function.
    CALLER = "caller"
    #: A function the primary function calls.
    CALLEE = "callee"
    #: A cleanup label, or the definition of a release function called on an
    #: error path.
    CLEANUP_PATH = "cleanup_path"
    #: The declaration of a file-scope variable the primary function touches.
    GLOBAL_DECL = "global_decl"
    #: An analyzer message. The only unit that carries prose rather than code.
    ANALYZER_MESSAGE = "analyzer_message"


_CLASS_OF: Final[dict[UnitRole, UnitClass]] = {
    UnitRole.CONTAINING_FUNCTION: UnitClass.PRIMARY,
    UnitRole.CANDIDATE_SITE: UnitClass.PRIMARY,
    # Primary for the same reason the others are: dropping it would leave the
    # control with no code at all, and a control that silently measures an
    # empty context is not a control.
    UnitRole.FLAT_WINDOW: UnitClass.PRIMARY,
    UnitRole.FLOW_FUNCTION: UnitClass.PRIMARY,
    UnitRole.TYPE_DECL: UnitClass.PRIMARY,
    UnitRole.MACRO_DEF: UnitClass.PRIMARY,
    UnitRole.CALLER: UnitClass.SUPPORTING,
    UnitRole.CALLEE: UnitClass.SUPPORTING,
    UnitRole.CLEANUP_PATH: UnitClass.SUPPORTING,
    UnitRole.GLOBAL_DECL: UnitClass.SUPPORTING,
    UnitRole.ANALYZER_MESSAGE: UnitClass.SECONDARY,
}

#: The role a region plays in the finished argument, for part 03's evidence
#: model. A caller's body is supporting code even though a call edge is the
#: reason it was retrieved: the bytes are a function, not an edge.
_KIND_OF: Final[dict[UnitRole, EvidenceKind]] = {
    UnitRole.CONTAINING_FUNCTION: EvidenceKind.PRIMARY_CODE,
    UnitRole.CANDIDATE_SITE: EvidenceKind.PRIMARY_CODE,
    UnitRole.FLAT_WINDOW: EvidenceKind.PRIMARY_CODE,
    UnitRole.FLOW_FUNCTION: EvidenceKind.PRIMARY_CODE,
    UnitRole.TYPE_DECL: EvidenceKind.TYPE_DECL,
    UnitRole.MACRO_DEF: EvidenceKind.MACRO_DEF,
    UnitRole.CALLER: EvidenceKind.SUPPORTING_CODE,
    UnitRole.CALLEE: EvidenceKind.SUPPORTING_CODE,
    UnitRole.CLEANUP_PATH: EvidenceKind.SUPPORTING_CODE,
    UnitRole.GLOBAL_DECL: EvidenceKind.SUPPORTING_CODE,
    UnitRole.ANALYZER_MESSAGE: EvidenceKind.ANALYZER_DIAGNOSTIC,
}

#: Relevance in thousandths, before depth and dataflow adjustments. Ordered so
#: that the plan's expansion order falls out of the numbers: the containing
#: function outranks the closure, a direct caller outranks a distant one, and
#: an analyzer message ranks below every line of code.
_BASE: Final[dict[UnitRole, int]] = {
    UnitRole.CONTAINING_FUNCTION: 1000,
    UnitRole.CANDIDATE_SITE: 1000,
    UnitRole.FLAT_WINDOW: 1000,
    UnitRole.FLOW_FUNCTION: 950,
    UnitRole.TYPE_DECL: 900,
    UnitRole.MACRO_DEF: 890,
    UnitRole.CALLER: 700,
    # Above CALLEE on purpose. A release function reached from an error path is
    # the callee that decides a resource-lifetime candidate, and when the two
    # roles select the same function this is the one the reader should be told
    # about.
    UnitRole.CLEANUP_PATH: 660,
    UnitRole.CALLEE: 650,
    UnitRole.GLOBAL_DECL: 500,
    UnitRole.ANALYZER_MESSAGE: 200,
}

#: Charged per call-graph hop beyond the first.
_DEPTH_PENALTY: Final = 100

#: Added when the unit's region contains a step of the analyzer's own reported
#: path. That is dataflow proximity measured rather than assumed, and the spec
#: ranks it above call-graph distance.
_DATAFLOW_BONUS: Final = 150

_SCALE: Final = 1000


def class_of(role: UnitRole) -> UnitClass:
    """The class a role always has. Never a per-unit decision."""
    return _CLASS_OF[role]


def evidence_kind_of(role: UnitRole) -> EvidenceKind:
    """The :class:`~caudit.model.evidence.EvidenceKind` a role's region carries."""
    return _KIND_OF[role]


def relevance(role: UnitRole, *, depth: int = 1, on_dataflow_path: bool = False) -> float:
    """A unit's rank within its class, in ``[0.0, 1.0]``.

    ``depth`` is the call-graph distance, counted from 1 for a direct
    caller or callee; it costs nothing for roles that have no distance.
    """
    points = _BASE[role] - max(0, depth - 1) * _DEPTH_PENALTY
    if on_dataflow_path:
        points += _DATAFLOW_BONUS
    return min(_SCALE, max(0, points)) / _SCALE


class ExpansionPolicy(BaseModel):
    """How far to expand. Versioned, because it changes what a run produces.

    ``version`` is recorded in the run manifest alongside the model ids: two
    reports that disagree about the same revision must be able to say whether
    they were even looking at the same code.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="1", min_length=1)
    #: Hops of callers to pull in, each as a complete function.
    caller_depth: int = Field(default=2, ge=0, le=8)
    #: Hops of callees. Shallower than callers by default: a callee's body is
    #: usually reachable from the call site the primary already contains,
    #: while the caller that supplies the input is not.
    callee_depth: int = Field(default=1, ge=0, le=8)
    include_cleanup_paths: bool = True
    include_global_decls: bool = True
    #: Hard cap on unit count, so a hot utility function with four hundred
    #: callers cannot exhaust the budget with breadth. Truncating the caller
    #: set is a recorded drop, never a silent cut.
    max_units: int = Field(default=64, ge=1, le=4096)
    #: How far to follow one type to the types it names. A struct whose field
    #: is another struct is one hop; the default reaches that layout without
    #: walking an entire header graph. Raising it raises the chance that the
    #: primary set alone exceeds the budget, which sends candidates to review
    #: rather than shrinking their context.
    type_closure_depth: int = Field(default=2, ge=1, le=16)
    #: How context is gathered. Anything but ``structural`` is an ablation.
    variant: RetrievalVariant = RetrievalVariant.STRUCTURAL
    #: Lines either side of the diagnostic under the ``flat_window`` control.
    #: The default spans 81 lines, which is the order of a mid-sized C function
    #: — the control is only informative if it reads a comparable amount of
    #: code, and a window nobody could defend as a fair comparison would make
    #: structural retrieval look good for the wrong reason.
    flat_window_lines: int = Field(default=40, ge=1, le=2000)

    @model_validator(mode="after")
    def _refuse_unimplemented_variants(self) -> Self:
        if self.variant is RetrievalVariant.STRUCTURAL_PLUS_SEMANTIC:
            raise ValueError(
                "the structural_plus_semantic retrieval variant is not implemented: "
                "part 09 puts embedding and BM25 retrieval out of scope, and no "
                "semantic retriever has been built. Refusing here rather than "
                "running structural retrieval under a semantic label"
            )
        return self

    @classmethod
    def from_config(cls, config: Config) -> ExpansionPolicy:
        """The policy for one run, from configuration.

        ``policy_versions.retrieval`` is the string the run manifest records.
        Taking it from there rather than from a constant in this file is what
        keeps the two honest: a report naming a retrieval version that the
        retrieval did not actually run under is worse than one naming none.

        Every depth knob is read here too. They were defaults-only until part
        13 needed to vary caller depth in an ablation, and a factor an
        experiment cannot set is a factor nobody can measure — the grid would
        have reported "no effect" for a knob that never moved.
        """
        retrieval = config.retrieval
        return cls(
            version=config.policy_versions.retrieval,
            caller_depth=retrieval.caller_depth,
            callee_depth=retrieval.callee_depth,
            include_cleanup_paths=retrieval.include_cleanup_paths,
            include_global_decls=retrieval.include_global_decls,
            max_units=retrieval.max_units,
            type_closure_depth=retrieval.type_closure_depth,
            variant=RetrievalVariant(retrieval.variant),
            flat_window_lines=retrieval.flat_window_lines,
        )


#: The policy a run uses unless configuration says otherwise.
DEFAULT_POLICY: Final = ExpansionPolicy()
