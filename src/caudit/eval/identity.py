"""Content identities for candidate sets and benchmark corpora."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Final

from caudit.eval.case import BenchmarkCase
from caudit.evidence.hashing import hash_bytes
from caudit.model.candidate import Candidate

__all__ = ["candidate_set_hash", "canonical_hash", "corpus_hash"]

_SOURCE_SUFFIXES: Final = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc"}
)


def canonical_hash(value: object) -> str:
    """SHA-256 over stable, compact JSON."""
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hash_bytes(payload.encode("utf-8"))


def candidate_set_hash(candidates_by_case: Mapping[str, Sequence[Candidate]]) -> str:
    """Identity of every candidate visible to either paired condition."""
    payload = [
        {
            "case_id": case_id,
            "candidates": [
                candidate.model_dump(mode="json")
                for candidate in sorted(
                    candidates_by_case[case_id],
                    key=lambda item: (item.candidate_id, item.fingerprint),
                )
            ],
        }
        for case_id in sorted(candidates_by_case)
    ]
    return canonical_hash(payload)


def corpus_hash(cases: Sequence[BenchmarkCase]) -> str:
    """Identity of labels, selected cases, source bytes, and build databases."""
    payload: list[dict[str, object]] = []
    for case in sorted(cases, key=lambda item: item.case_id):
        root = case.root.resolve()
        files = [
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hash_bytes(path.read_bytes()),
            }
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.suffix.lower() in _SOURCE_SUFFIXES
        ]
        database = None
        if case.compile_commands is not None and case.compile_commands.is_file():
            database = {
                "sha256": hash_bytes(case.compile_commands.read_bytes()),
                "name": case.compile_commands.name,
            }
        payload.append(
            {
                "case_id": case.case_id,
                "ground_truth": [
                    truth.model_dump(mode="json")
                    for truth in sorted(
                        case.ground_truth,
                        key=lambda item: (str(item.path), item.line, str(item.cwe), item.variant),
                    )
                ],
                "family": str(case.family) if case.family is not None else None,
                "lines_of_code": case.lines_of_code,
                "analyzer_blind_spot": case.analyzer_blind_spot,
                "files": files,
                "compile_commands": database,
            }
        )
    return canonical_hash(payload)
