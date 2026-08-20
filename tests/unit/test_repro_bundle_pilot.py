"""Reproducible public bundles and repeated-pilot contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from caudit.cli.pilot_cmd import select_castle_pilot_cases
from caudit.eval.pilot import PilotRepetition, RepeatedCastlePilot
from caudit.eval.repro_bundle import (
    build_reproducible_bundle,
    verify_reproducible_bundle,
)


def test_identical_artifacts_produce_byte_identical_verified_bundles(tmp_path: Path) -> None:
    artifacts = tmp_path / "results"
    artifacts.mkdir()
    (artifacts / "metrics.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "suite": "mini",
                    "precision": 1.0,
                    "recall": 0.5,
                    "macro_f2": 0.6,
                    "confirmed_count": 2,
                    "review_required_count": 1,
                },
                "experiment": {"condition": "attribution_a0"},
            }
        ),
        encoding="utf-8",
    )
    (artifacts / "notes.md").write_text("# Notes\n", encoding="utf-8")
    forbidden = artifacts / "prompts"
    forbidden.mkdir()
    (forbidden / "source.txt").write_text("secret source", encoding="utf-8")

    first, manifest = build_reproducible_bundle(
        root=tmp_path,
        inputs=[Path("results")],
        output=tmp_path / "first.tar",
    )
    second, _ = build_reproducible_bundle(
        root=tmp_path,
        inputs=[Path("results")],
        output=tmp_path / "second.tar",
    )

    assert first.read_bytes() == second.read_bytes()
    assert len(manifest.artifacts) == 2
    verified = verify_reproducible_bundle(first)
    assert verified == manifest
    assert all("prompts" not in item.path for item in manifest.artifacts)


class _Cases:
    def case_ids(self) -> tuple[str, ...]:
        return ("125-1", "125-2", "190-1", "190-2", "476-1", "476-2")


def test_castle_selection_is_seeded_and_stratified() -> None:
    first = select_castle_pilot_cases(_Cases(), seed=7)  # type: ignore[arg-type]
    second = select_castle_pilot_cases(_Cases(), seed=7)  # type: ignore[arg-type]

    assert first == second
    assert len(first) == 3
    assert {case.split("-", 1)[0] for case in first} == {"125", "190", "476"}


def test_pilot_requires_a_record_for_every_planned_repetition() -> None:
    with pytest.raises(ValidationError, match="every requested repetition"):
        RepeatedCastlePilot(
            selection_seed=1,
            selection_algorithm="fixture",
            case_ids=["125-1"],
            requested_repetitions=2,
            stopping_rule="exactly two",
            cold_repetition_definition="fresh output",
            repetitions=[PilotRepetition(repetition=1, status="failed", failure="fixture")],
            candidate_identity_stable=False,
            corpus_identity_stable=False,
            result_stable=False,
        )
