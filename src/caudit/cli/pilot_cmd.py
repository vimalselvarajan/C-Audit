"""Run a repeated, stratified CASTLE analyzer-control pilot."""

from __future__ import annotations

import random
from io import StringIO
from pathlib import Path

from rich.console import Console

from caudit.cli.eval_cmd import run_eval
from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.eval.adapters.castle import CastleSuite
from caudit.eval.compare import load_run_report
from caudit.eval.pilot import PilotRepetition, RepeatedCastlePilot, write_castle_pilot

__all__ = ["run_castle_pilot", "select_castle_pilot_cases"]


def select_castle_pilot_cases(suite: CastleSuite, *, seed: int) -> list[str]:
    """Select one case per in-scope CWE with a recorded, reproducible seed."""

    groups: dict[str, list[str]] = {}
    for case_id in suite.case_ids():
        groups.setdefault(case_id.split("-", 1)[0], []).append(case_id)
    rng = random.Random(seed)
    return sorted(rng.choice(sorted(case_ids)) for _cwe, case_ids in sorted(groups.items()))


def run_castle_pilot(
    *,
    config: Config,
    out_dir: Path,
    summary_path: Path,
    repetitions: int = 5,
    seed: int = 20260820,
) -> RepeatedCastlePilot:
    """Repeat real analyzer generation; record success and failure alike."""

    suite = CastleSuite()
    if not suite.is_available():
        suite.ensure_available()
    case_ids = select_castle_pilot_cases(suite, seed=seed)
    records: list[PilotRepetition] = []
    for number in range(1, repetitions + 1):
        repetition_dir = out_dir / f"repetition-{number:02d}"
        try:
            run_eval(
                config=config,
                suite="castle",
                baseline=True,
                out_dir=repetition_dir,
                case_ids=tuple(case_ids),
                console=Console(file=StringIO(), width=200),
                use_clang=True,
            )
            report_path = repetition_dir / "metrics-castle.json"
            report = load_run_report(report_path)
            experiment = report.experiment
            if experiment is None:
                raise CauditError("CASTLE pilot run did not write an experiment manifest")
            records.append(
                PilotRepetition(
                    repetition=number,
                    status="completed",
                    report=str(report_path.relative_to(out_dir)),
                    candidate_set_hash=experiment.candidate_set_hash,
                    corpus_hash=experiment.corpus_hash,
                    precision=report.metrics.precision,
                    recall=report.metrics.recall,
                    macro_f2=report.metrics.macro_f2,
                )
            )
        except (CauditError, OSError, ValueError) as exc:
            records.append(
                PilotRepetition(
                    repetition=number,
                    status="failed",
                    failure=f"{type(exc).__name__}: {exc}",
                )
            )

    completed = [record for record in records if record.status == "completed"]
    candidate_hashes = {record.candidate_set_hash for record in completed}
    corpus_hashes = {record.corpus_hash for record in completed}
    scores = {(record.precision, record.recall, record.macro_f2) for record in completed}
    pilot = RepeatedCastlePilot(
        selection_seed=seed,
        selection_algorithm=(
            "group in-scope case ids by CWE prefix; sort groups and members; "
            "Python MT19937 choice of one member per group"
        ),
        case_ids=case_ids,
        requested_repetitions=repetitions,
        stopping_rule=f"exactly {repetitions} repetitions; failures do not extend the run",
        cold_repetition_definition=(
            "real analyzer candidate generation runs again into a fresh output directory; "
            "no model or response cache participates"
        ),
        repetitions=records,
        candidate_identity_stable=bool(completed) and len(candidate_hashes) == 1,
        corpus_identity_stable=bool(completed) and len(corpus_hashes) == 1,
        result_stable=bool(completed) and len(scores) == 1,
    )
    write_castle_pilot(pilot, summary_path)
    return pilot
