"""Part 09 path tests: T-09-05, T-09-06, T-09-16, T-09-19.

Covers AC-09-4, AC-09-5, AC-09-12. Callers and callees come back as complete
functions, cleanup paths are addressable rather than merely present, and the
whole thing is independent of the order the index happened to iterate.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from caudit.config.loader import Config
from caudit.evidence.store import SourceStore
from caudit.index.store import Index, IndexSnapshot
from caudit.model.finding import LimitationKind
from caudit.retrieval.paths import is_release_call
from caudit.retrieval.policy import DEFAULT_POLICY, ExpansionPolicy, UnitClass, UnitRole
from caudit.retrieval.service import expand, zoom
from tests.conftest import retrieval_candidate, retrieval_world

pytestmark = pytest.mark.needs_libclang


def _named(context: object, role: UnitRole) -> set[str]:
    return {
        unit.symbol.name
        for unit in context.units_with_role(role)  # type: ignore[attr-defined]
        if unit.symbol is not None
    }


# ---------------------------------------------------------------- T-09-05


def test_callers_and_callees_arrive_complete_at_the_configured_depth(
    tmp_path: Path,
) -> None:
    """T-09-05, AC-09-4: three callers, two callees, depth 2 and 1."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(
        retrieval_candidate(store, "expansion.c", 120),
        index,
        store,
        ExpansionPolicy(caller_depth=2, callee_depth=1),
        allowance=50_000,
    )

    # caller_a/b/c call long_walk directly; outer calls caller_a, so it is the
    # second hop and is present because caller_depth is 2.
    assert _named(context, UnitRole.CALLER) == {"caller_a", "caller_b", "caller_c", "outer"}
    assert _named(context, UnitRole.CALLEE) == {"helper_one", "helper_two"}

    for unit in context.units_with_role(UnitRole.CALLER) + context.units_with_role(UnitRole.CALLEE):
        assert unit.symbol is not None and unit.symbol.usr is not None
        symbol = index.symbol(unit.symbol.usr)
        assert symbol is not None and symbol.definition is not None
        # Complete each: the whole body, not the call site.
        assert (unit.region.start_line, unit.region.end_line) == (
            symbol.definition.start_line,
            symbol.definition.end_line,
        )
        assert zoom(context, unit.evidence_id).rstrip().endswith(b"}")
        assert unit.unit_class is UnitClass.SUPPORTING


def test_depth_is_recorded_and_ranks_a_distant_caller_lower(tmp_path: Path) -> None:
    """AC-09-4: call-graph distance is the ranking signal, so it is stored."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(
        retrieval_candidate(store, "expansion.c", 120),
        index,
        store,
        ExpansionPolicy(caller_depth=2),
        allowance=50_000,
    )

    by_name = {
        unit.symbol.name: unit
        for unit in context.units_with_role(UnitRole.CALLER)
        if unit.symbol is not None
    }
    assert by_name["caller_a"].depth == 1
    assert by_name["outer"].depth == 2
    assert by_name["outer"].relevance < by_name["caller_a"].relevance


def test_depth_zero_asks_for_nothing(tmp_path: Path) -> None:
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(
        retrieval_candidate(store, "expansion.c", 120),
        index,
        store,
        ExpansionPolicy(caller_depth=0, callee_depth=0),
        allowance=50_000,
    )
    assert context.units_with_role(UnitRole.CALLER) == []
    assert context.units_with_role(UnitRole.CALLEE) == []
    # The containing function and its closure are unaffected: they are not
    # reached through the call graph.
    assert context.units_with_role(UnitRole.CONTAINING_FUNCTION)


def test_a_callee_with_no_body_in_the_index_is_named_rather_than_dropped(
    tmp_path: Path,
) -> None:
    """`local_alloc` is declared here and defined nowhere this run parsed."""
    _root, index, store = retrieval_world(tmp_path, "cleanup")
    context = expand(retrieval_candidate(store, "cleanup.c", 51), index, store)

    missing = [
        limitation
        for limitation in context.limitations
        if limitation.kind is LimitationKind.NO_EVIDENCE_EXPANSION
        and "no parsed translation unit contained its body" in limitation.detail
    ]
    assert {"local_alloc", "local_free"} <= {
        word for limitation in missing for word in limitation.detail.split()
    }


# ---------------------------------------------------------------- T-09-06


def test_the_cleanup_label_and_both_release_sites_are_addressable(tmp_path: Path) -> None:
    """T-09-06, AC-09-5: a leak candidate with `goto cleanup` and two frees."""
    root, index, store = retrieval_world(tmp_path, "cleanup")
    context = expand(
        retrieval_candidate(store, "cleanup.c", 51, cwe=("CWE-401",)),
        index,
        store,
        allowance=50_000,
    )

    cleanup = context.units_with_role(UnitRole.CLEANUP_PATH)
    texts = {zoom(context, unit.evidence_id).decode("utf-8") for unit in cleanup}

    # The label block, from `cleanup:` to the end of the function.
    assert any(text.startswith("cleanup:") for text in texts)
    # Both release sites, each on its own so a claim can cite the exact line.
    assert any(text.strip() == "local_free(scratch.data);" for text in texts)
    assert any(text.strip() == "buffer_release(&scratch);" for text in texts)
    # And the body of the in-repo release function, because a name that reads
    # like a release is not a release until you have read it.
    assert any(text.startswith("void buffer_release(") for text in texts)

    source = (root / "cleanup.c").read_text(encoding="utf-8").split("\n")
    label_line = source.index("cleanup:") + 1
    assert any(unit.region.start_line == label_line for unit in cleanup)


def test_cleanup_expansion_is_a_policy_choice(tmp_path: Path) -> None:
    _root, index, store = retrieval_world(tmp_path, "cleanup")
    context = expand(
        retrieval_candidate(store, "cleanup.c", 51),
        index,
        store,
        ExpansionPolicy(include_cleanup_paths=False),
        allowance=50_000,
    )
    assert context.units_with_role(UnitRole.CLEANUP_PATH) == []


def test_a_function_with_no_goto_gets_no_label_block(tmp_path: Path) -> None:
    """The label scan reads code that is already present; it invents nothing."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    context = expand(retrieval_candidate(store, "expansion.c", 120), index, store, allowance=50_000)
    assert context.units_with_role(UnitRole.CLEANUP_PATH) == []


def test_an_unresolved_indirect_call_makes_the_caller_set_a_lower_bound(
    tmp_path: Path,
) -> None:
    """The part 06 invariant, carried into retrieval.

    `dispatch` calls through a function-pointer table. Any function in the
    index could be reached that way, so a caller set retrieved for
    `accept_all` is a floor, not a census — and the context has to say so,
    because a model shown three callers will otherwise reason as if there were
    exactly three.
    """
    _root, index, store = retrieval_world(tmp_path, "indirect")
    context = expand(retrieval_candidate(store, "indirect.c", 8), index, store, allowance=50_000)

    lower_bound = [
        limitation
        for limitation in context.limitations
        if limitation.kind is LimitationKind.UNRESOLVED_INDIRECT_CALL
        and "lower bound" in limitation.detail
    ]
    assert lower_bound, [limitation.detail for limitation in context.limitations]
    assert "accept_all" in lower_bound[0].detail
    # The resolved caller is still retrieved: the limitation is about what
    # might be missing, never a reason to withhold what was found.
    assert "direct" in _named(context, UnitRole.CALLER)


def test_a_callee_set_with_an_unresolved_site_says_so_too(tmp_path: Path) -> None:
    """`dispatch`'s own callees are a floor for the same reason."""
    _root, index, store = retrieval_world(tmp_path, "indirect")
    context = expand(retrieval_candidate(store, "indirect.c", 24), index, store, allowance=50_000)

    details = [
        limitation.detail
        for limitation in context.limitations
        if limitation.kind is LimitationKind.UNRESOLVED_INDIRECT_CALL
    ]
    assert any("reached through a function pointer is not on the page" in text for text in details)


def test_the_release_lexicon_is_shape_based_not_a_fixed_list() -> None:
    assert is_release_call("free")
    assert is_release_call("pthread_mutex_unlock")
    assert is_release_call("buffer_release")
    assert is_release_call("destroy_widget")
    assert not is_release_call("malloc")
    assert not is_release_call("compute")
    assert not is_release_call(None)


# ---------------------------------------------------------------- T-09-16


def test_shuffling_the_index_iteration_order_changes_nothing(tmp_path: Path) -> None:
    """T-09-16, AC-09-12: same inputs, same units, same order."""
    root, index, store = retrieval_world(tmp_path, "expansion")
    candidate = retrieval_candidate(store, "expansion.c", 120, flow=(120, 44))

    reference = expand(candidate, index, store, allowance=50_000)

    rng = random.Random(20260812)
    snapshot = index.to_snapshot()
    for _attempt in range(5):
        shuffled = IndexSnapshot(
            format_version=snapshot.format_version,
            libclang=snapshot.libclang,
            revision=snapshot.revision,
            units=rng.sample(snapshot.units, len(snapshot.units)),
            symbols=rng.sample(snapshot.symbols, len(snapshot.symbols)),
            calls=rng.sample(snapshot.calls, len(snapshot.calls)),
            macros=rng.sample(snapshot.macros, len(snapshot.macros)),
            includes=rng.sample(snapshot.includes, len(snapshot.includes)),
            type_references=rng.sample(snapshot.type_references, len(snapshot.type_references)),
            global_references=rng.sample(
                snapshot.global_references, len(snapshot.global_references)
            ),
            limitations=rng.sample(snapshot.limitations, len(snapshot.limitations)),
        )
        other = Index.from_snapshot(shuffled, repo_root=root)
        again = expand(candidate, index=other, store=store, allowance=50_000)

        assert [unit.evidence_id for unit in again.units] == [
            unit.evidence_id for unit in reference.units
        ]
        assert [unit.role for unit in again.units] == [unit.role for unit in reference.units]
        assert again.total_tokens == reference.total_tokens
        assert again.limitations == reference.limitations


def test_two_expansions_of_one_candidate_agree(tmp_path: Path) -> None:
    """AC-09-12: nothing in expansion reads a clock or a hash seed."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    candidate = retrieval_candidate(store, "expansion.c", 120)

    first = expand(candidate, index, store, allowance=50_000)
    second = expand(candidate, index, store, allowance=50_000)

    assert first.units == second.units
    assert first.dropped == second.dropped
    assert first.limitations == second.limitations


# ---------------------------------------------------------------- T-09-19


@pytest.mark.slow
def test_five_hundred_candidates_reuse_one_index(tmp_path: Path) -> None:
    """T-09-19: expansion throughput, and the index built once."""
    _root, index, store = retrieval_world(tmp_path, "expansion")
    parses_after_build = index.stats.parsed

    started = time.monotonic()
    contexts = [
        expand(retrieval_candidate(store, "expansion.c", 50 + (step % 150)), index, store)
        for step in range(500)
    ]
    elapsed = time.monotonic() - started

    assert len(contexts) == 500
    assert all(context.units for context in contexts)
    # Nothing re-parsed: retrieval asks the index, it does not rebuild it.
    assert index.stats.parsed == parses_after_build
    assert elapsed < 60.0, f"500 expansions took {elapsed:.1f}s"


def test_the_default_policy_is_the_one_the_plan_names() -> None:
    """The version is recorded per run, so it is worth pinning here."""
    assert DEFAULT_POLICY.version == "1"
    assert DEFAULT_POLICY.caller_depth == 2
    assert DEFAULT_POLICY.callee_depth == 1
    assert DEFAULT_POLICY.include_cleanup_paths
    assert DEFAULT_POLICY.include_global_decls


def test_the_policy_version_is_the_one_the_manifest_will_record() -> None:
    """Two independent constants spelling "1" is a drift waiting to happen.

    The manifest records `policy_versions.retrieval`; the policy has to be the
    same string, or a run is reproducible only by coincidence.
    """
    config = Config()
    assert ExpansionPolicy.from_config(config).version == config.policy_versions.retrieval
    assert DEFAULT_POLICY.version == config.policy_versions.retrieval

    bumped = Config.model_validate({"policy_versions": {"retrieval": "7"}})
    assert ExpansionPolicy.from_config(bumped).version == "7"


def test_the_store_and_the_index_must_describe_one_revision(tmp_path: Path) -> None:
    """A sanity guard on the fixture helper, not on production code."""
    _root, index, store = retrieval_world(tmp_path, "cleanup")
    assert isinstance(store, SourceStore)
    assert store.revision == index.revision
