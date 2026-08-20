"""Pipeline stage bookkeeping independent of orchestration decisions."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from types import TracebackType

from caudit.errors import CauditError
from caudit.logging import get_logger
from caudit.model.finding import Limitation, LimitationKind
from caudit.model.manifest import StageRecord, StageStatus

log = get_logger(__name__)


class Stage(StrEnum):
    """The stages of one scan, in execution order."""

    INTAKE = "intake"
    INDEX = "index"
    CANDIDATES = "candidates"
    EXPANSION = "expansion"
    ADJUDICATION = "adjudication"
    VERIFICATION = "verification"
    REPORT = "report"


@dataclass
class StageNote:
    """A running stage can record a degraded, observed, or skipped outcome."""

    status: StageStatus = StageStatus.OK
    detail: str | None = None

    def degraded(self, detail: str) -> None:
        self.status = StageStatus.DEGRADED
        self.detail = detail

    def observe(self, detail: str) -> None:
        self.detail = detail

    def skipped(self, detail: str) -> None:
        self.status = StageStatus.SKIPPED
        self.detail = detail


@dataclass
class StageLog:
    """Record stage status and duration while letting typed failures degrade."""

    records: list[StageRecord] = field(default_factory=list)
    clock: Callable[[], float] = time.monotonic

    @contextmanager
    def timed(self, stage: Stage, *, degrade: bool = False) -> Iterator[StageNote]:
        note = StageNote()
        started = self.clock()
        try:
            yield note
        except CauditError as exc:
            if not degrade:
                raise
            self._append(stage, StageStatus.FAILED, self.clock() - started, exc.render())
            log.warning("stage %s failed; continuing with a partial report: %s", stage, exc)
            return
        self._append(stage, note.status, self.clock() - started, note.detail)

    def _append(
        self, stage: Stage, status: StageStatus, seconds: float, detail: str | None
    ) -> None:
        self.records.append(
            StageRecord(
                stage=str(stage),
                status=status,
                duration_seconds=max(0.0, seconds),
                detail=detail,
            )
        )

    @property
    def partial(self) -> bool:
        return any(
            record.status in (StageStatus.FAILED, StageStatus.DEGRADED) for record in self.records
        )

    def limitations(self) -> list[Limitation]:
        """Turn failed or degraded stages into visible report limitations."""
        return [
            Limitation(
                kind=LimitationKind.TOOLCHAIN_UNAVAILABLE,
                detail=(
                    f"the {record.stage} stage {record.status}: {record.detail}. This "
                    "report is partial — what that stage would have contributed is "
                    "missing, not absent"
                ),
                affects=None,
            )
            for record in self.records
            if record.status in (StageStatus.FAILED, StageStatus.DEGRADED)
        ]

    def __enter__(self) -> StageLog:  # pragma: no cover
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:  # pragma: no cover
        return None
