"""Content-addressed candidate and corpus identity."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from caudit.eval.case import BenchmarkCase, GroundTruth
from caudit.eval.identity import candidate_set_hash, corpus_hash
from caudit.model.cwe import WeaknessFamily
from caudit.model.evidence import Provenance
from tests.conftest import make_candidate


def test_candidate_set_hash_is_order_independent(provenance: list[Provenance]) -> None:
    first = make_candidate(provenance, message="first")
    second = make_candidate(provenance, message="second")

    left = candidate_set_hash({"b": [second, first], "a": [first]})
    right = candidate_set_hash({"a": [first], "b": [first, second]})

    assert left == right
    assert len(left) == 64


def test_candidate_set_hash_changes_when_candidate_content_changes(
    provenance: list[Provenance],
) -> None:
    first = make_candidate(provenance, message="first")
    changed = make_candidate(provenance, message="changed")

    assert candidate_set_hash({"case": [first]}) != candidate_set_hash({"case": [changed]})


def test_corpus_hash_covers_labels_source_bytes_and_database(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    database = tmp_path / "compile_commands.json"
    database.write_text("[]\n", encoding="utf-8")
    case = BenchmarkCase(
        case_id="case",
        root=tmp_path,
        compile_commands=database,
        ground_truth=[
            GroundTruth(
                path=PurePosixPath("sample.c"),
                line=1,
                cwe="CWE-787",
                family=WeaknessFamily.OUT_OF_BOUNDS,
            )
        ],
        lines_of_code=1,
        family=WeaknessFamily.OUT_OF_BOUNDS,
    )

    original = corpus_hash([case])
    source.write_text("int main(void) { return 1; }\n", encoding="utf-8")
    source_changed = corpus_hash([case])
    database.write_text("[{}]\n", encoding="utf-8")
    database_changed = corpus_hash([case])
    relabelled = corpus_hash(
        [
            case.model_copy(
                update={"ground_truth": [case.ground_truth[0].model_copy(update={"line": 2})]}
            )
        ]
    )

    assert len(original) == 64
    assert original != source_changed
    assert source_changed != database_changed
    assert database_changed != relabelled
