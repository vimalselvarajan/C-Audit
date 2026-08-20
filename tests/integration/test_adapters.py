"""Part 04 corpus tests: T-04-19, T-04-20.

The two corpus tests are deselected by default. They need corpora that are
fetched once, pinned by revision, and cached outside the repository — which
is exactly why the mini suite exists for CI. Everything else in this module
exercises the adapters' logic without any download.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caudit.errors import CauditError
from caudit.eval.adapters.castle import CastleSuite, cache_root
from caudit.eval.adapters.juliet import JULIET_PINNED_CWES, JulietSuite
from caudit.eval.adapters.mini import MiniSuite
from caudit.model.cwe import WeaknessFamily, family_of


def test_castle_adapter_refuses_to_fetch_implicitly(tmp_path: Path) -> None:
    """An absent corpus is an actionable message, never a silent download."""
    suite = CastleSuite(tmp_path / "castle")
    assert not suite.is_available()
    assert suite.case_ids() == ()
    with pytest.raises(CauditError) as excinfo:
        suite.ensure_available()
    assert "git clone" in (excinfo.value.hint or "")


def test_juliet_adapter_refuses_to_fetch_implicitly(tmp_path: Path) -> None:
    suite = JulietSuite(tmp_path / "juliet")
    assert not suite.is_available()
    with pytest.raises(CauditError) as excinfo:
        suite.ensure_available()
    hint = excinfo.value.hint or ""
    assert "samate.nist.gov" in hint
    for cwe in ("CWE-121", "CWE-416", "CWE-134"):
        assert cwe in hint


def test_cache_root_is_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAUDIT_BENCHMARK_CACHE", "/tmp/caudit-bench")
    assert cache_root() == Path("/tmp/caudit-bench")


def test_juliet_pins_cover_every_in_scope_family() -> None:
    """A pinned subset that skipped a family would silently stop scoring it."""
    covered = set(JULIET_PINNED_CWES.values())
    assert covered == set(WeaknessFamily)
    for cwe in JULIET_PINNED_CWES:
        assert family_of(cwe) is not None, f"{cwe} is not in the allowlist"


def test_juliet_twin_detection_on_a_synthetic_case(tmp_path: Path) -> None:
    """T-04-20 in miniature: good/bad pairing without downloading Juliet.

    The corpus test below needs the real download; this one proves the
    pairing logic itself, which is what makes precision meaningful.
    """
    root = tmp_path / "juliet"
    directory = root / "CWE121_Stack_Based_Buffer_Overflow"
    directory.mkdir(parents=True)
    source = directory / "CWE121_example_01.c"
    source.write_text(
        "#include <string.h>\n"
        "\n"
        "void bad(void)\n"
        "{\n"
        "    char buf[4];\n"
        '    strcpy(buf, "far too long");\n'
        "}\n"
        "\n"
        "void good1(void)\n"
        "{\n"
        "    char buf[32];\n"
        '    strncpy(buf, "safe", sizeof(buf) - 1);\n'
        "}\n",
        encoding="utf-8",
    )
    suite = JulietSuite(root)
    assert suite.is_available()
    case = suite.load("CWE121_example_01")
    variants = {truth.variant: truth.line for truth in case.ground_truth}
    assert variants == {"vulnerable": 3, "fixed": 9}
    assert all(truth.cwe == "CWE-121" for truth in case.ground_truth)
    assert case.family is WeaknessFamily.OUT_OF_BOUNDS


def _castle_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """A CASTLE checkout in the corpus's real shape, not an assumed one.

    Flat sources under ``datasets/CASTLE-C250/`` and one central manifest —
    which is what CASTLE ships. The previous fixture built per-case JSON
    sidecars and inline ``// bad`` markers, neither of which exists upstream,
    so the adapter it tested could not have read the real corpus and the test
    passed anyway.
    """
    root = tmp_path / "castle"
    sources = root / "datasets" / "CASTLE-C250"
    sources.mkdir(parents=True)
    (sources / "CASTLE-125-1.c").write_text(
        "int read_it(const int *a)\n{\n    return a[5];\n}\n",
        encoding="utf-8",
    )
    (sources / "CASTLE-125-7.c").write_text(
        "int read_it(const int *a, int n)\n{\n    return n > 5 ? a[5] : 0;\n}\n",
        encoding="utf-8",
    )
    # CWE-89 is real CASTLE content and outside the allowlist; it must be
    # skipped with a count rather than loaded or silently dropped.
    (sources / "CASTLE-89-1.c").write_text("int q(void)\n{\n    return 0;\n}\n", encoding="utf-8")
    manifest = root / "datasets" / "CASTLE-C250.json"
    manifest.write_text(
        json.dumps(
            {
                "dataset": "CASTLE-Benchmark",
                "tests": [
                    {
                        "name": "CASTLE-125-1.c",
                        "id": "125-1",
                        "cwe": 125,
                        "vulnerable": True,
                        "lines": [3],
                        "compile": "gcc CASTLE-125-1.c -o CASTLE-125-1",
                        "description": "out-of-bounds read",
                    },
                    {
                        "name": "CASTLE-125-7.c",
                        "id": "125-7",
                        "cwe": 125,
                        "vulnerable": False,
                        "lines": [],
                        "compile": "gcc CASTLE-125-7.c -o CASTLE-125-7",
                        "description": "bounds are checked",
                    },
                    {
                        "name": "CASTLE-89-1.c",
                        "id": "89-1",
                        "cwe": 89,
                        "vulnerable": True,
                        "lines": [3],
                        "compile": "gcc CASTLE-89-1.c -o CASTLE-89-1",
                        "description": "SQL injection",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return root, tmp_path / "workspace"


def test_castle_reads_the_central_manifest(tmp_path: Path) -> None:
    """T-04-25: labels come from CASTLE-C250.json, in the shape it really has."""
    root, workspace = _castle_fixture(tmp_path)
    suite = CastleSuite(root, workspace)

    assert suite.is_available()
    case = suite.load("125-1")
    assert [t.cwe for t in case.ground_truth] == ["CWE-125"]
    assert case.ground_truth[0].line == 3
    assert str(case.ground_truth[0].path) == "CASTLE-125-1.c"
    assert case.family is WeaknessFamily.OUT_OF_BOUNDS


def test_castle_keeps_the_non_vulnerable_variants_as_false_positive_bait(
    tmp_path: Path,
) -> None:
    """T-04-26: 100 of CASTLE's 250 cases exist to be *not* reported.

    A safe case carries an empty ``lines`` array, so it gets no ground truth
    and every finding against it counts as a false positive. That is the only
    headroom on this corpus for adjudication to show a gain — the mini suite
    has no false positives at baseline, so nothing there can improve.
    """
    root, workspace = _castle_fixture(tmp_path)
    case = CastleSuite(root, workspace).load("125-7")

    assert case.ground_truth == [], "a non-vulnerable case must carry no truth entries"
    # Still attributed, so a false positive is charged to the right family
    # rather than to a fallback.
    assert case.family is WeaknessFamily.OUT_OF_BOUNDS


def test_castle_skips_out_of_scope_cwes_with_a_count(tmp_path: Path) -> None:
    """T-04-27: what the corpus lost is reported, never silently dropped."""
    root, workspace = _castle_fixture(tmp_path)
    suite = CastleSuite(root, workspace)

    assert set(suite.case_ids()) == {"125-1", "125-7"}
    assert suite.skipped() == {"CWE-89": 1}
    with pytest.raises(FileNotFoundError):
        suite.load("89-1")


def test_castle_stages_each_case_into_a_root_of_its_own(tmp_path: Path) -> None:
    """T-04-28: the flat corpus must not make every case span all 250 files.

    ``case.root`` bounds one case: the analyzer pass globs it for sources and
    intake measures coverage against it. Pointed at the shared directory, one
    case would analyse the whole corpus and report coverage of 1/250.
    """
    root, workspace = _castle_fixture(tmp_path)
    suite = CastleSuite(root, workspace)

    for case in suite.cases():
        sources = sorted(p.name for p in case.root.rglob("*.c"))
        assert len(sources) == 1, f"{case.case_id} sees {sources}"
        assert (case.root / str(case.ground_truth[0].path)).is_file() if case.ground_truth else True


def test_castle_builds_a_database_from_the_corpus_own_compile_line(tmp_path: Path) -> None:
    """T-04-29: flags come from CASTLE, not from this adapter's imagination.

    "Never guess include paths or compiler flags" applies to a benchmark too.
    CASTLE records ``gcc <file> -o <binary>``; analysis needs the configured
    compiler and no link step, so the driver is swapped and ``-c`` replaces the
    link output. Nothing else is added.
    """
    root, workspace = _castle_fixture(tmp_path)
    suite = CastleSuite(root, workspace)

    database = suite.materialize_compile_commands("125-1", tmp_path / "db")
    entries = json.loads(database.read_text(encoding="utf-8"))
    assert len(entries) == 1
    entry = entries[0]

    assert entry["arguments"][0] == "clang"
    assert "-c" in entry["arguments"]
    assert "-o" in entry["arguments"]
    # The link target is gone; nothing invented took its place.
    assert "CASTLE-125-1" not in entry["arguments"]
    assert Path(entry["file"]).is_file()
    assert Path(entry["directory"]).is_dir()


def test_mini_suite_materializes_a_real_compilation_database(tmp_path: Path) -> None:
    """The committed template carries a placeholder; absolute paths are not."""
    suite = MiniSuite()
    database = suite.materialize_compile_commands("oob-write-stack-copy", tmp_path)
    text = database.read_text(encoding="utf-8")
    assert "${CASE_ROOT}" not in text
    assert str(suite.root / "oob-write-stack-copy") in text

    entries = json.loads(text)
    assert entries
    for entry in entries:
        assert Path(entry["file"]).is_file()
        assert entry["arguments"][0] == "clang"


def test_every_mini_case_has_a_compile_commands_template() -> None:
    suite = MiniSuite()
    for case_id in suite.case_ids():
        assert (suite.root / case_id / "compile_commands.template.json").is_file()


@pytest.mark.slow
@pytest.mark.needs_clang
def test_castle_corpus_parses_at_least_one_case_per_covered_cwe() -> None:
    """T-04-19: requires a cached CASTLE checkout.

    The assertion that every case carries ground truth was wrong about the
    corpus and had to go: 100 of CASTLE's 250 cases are deliberately not
    vulnerable and carry none. What must hold is that every *vulnerable* case
    is labelled and that both variants are present, because a corpus that lost
    its safe half would measure only recall.
    """
    suite = CastleSuite()
    if not suite.is_available():
        pytest.skip(f"CASTLE is not cached at {suite.root}; see my_docs/guides/setup.md")
    cases = suite.cases()
    assert cases

    families = {truth.family for case in cases for truth in case.ground_truth}
    assert families, "no case carried usable ground truth"
    assert families <= CastleSuite.covered_families()

    labelled = [case for case in cases if case.ground_truth]
    safe = [case for case in cases if not case.ground_truth]
    assert labelled, "no vulnerable case is labelled"
    assert safe, "the false-positive half of the corpus is missing"
    for case in labelled:
        assert all(truth.line >= 1 for truth in case.ground_truth)
        assert (case.root / str(case.ground_truth[0].path)).is_file()


@pytest.mark.slow
def test_juliet_corpus_pairs_good_and_bad_twins() -> None:
    """T-04-20: requires an extracted Juliet subset."""
    suite = JulietSuite()
    if not suite.is_available():
        pytest.skip(f"Juliet is not cached at {suite.root}; see my_docs/guides/setup.md")
    paired = [
        case
        for case in suite.cases()
        if {truth.variant for truth in case.ground_truth} == {"vulnerable", "fixed"}
    ]
    assert paired, "no good/bad twin pairs were detected in the pinned directories"
