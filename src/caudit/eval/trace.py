"""JSONL run traces.

Ablations in part 13 need to compare runs that differ in one variable, which
is only possible if each run recorded the variables. A trace line carries the
case, the counts, the timings, the tool versions, and the policy version —
enough to tell two runs apart for a reason.

Traces are deterministic apart from timings, so two runs over the same suite
produce identical metrics even though their traces differ in duration.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Any, Self

__all__ = ["TraceWriter", "read_trace"]


class TraceWriter:
    """Appends one JSON object per line."""

    def __init__(
        self, path: Path, *, run_id: str, policy_version: str, tool_versions: Mapping[str, str]
    ) -> None:
        self.path = path
        self.run_id = run_id
        self.policy_version = policy_version
        self.tool_versions = dict(tool_versions)
        self._handle: Any = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("w", encoding="utf-8")
        self.write("run_started", tool_versions=self.tool_versions)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._handle is not None:
            self.write("run_finished", ok=exc_type is None)
            self._handle.close()
            self._handle = None

    def write(self, event: str, **fields: object) -> None:
        """One trace record. Keys are sorted so lines diff cleanly."""
        record: dict[str, object] = {
            "run_id": self.run_id,
            "event": event,
            "policy_version": self.policy_version,
            **fields,
        }
        if self._handle is None:  # pragma: no cover - misuse guard
            raise RuntimeError("TraceWriter used outside its context manager")
        self._handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        self._handle.flush()

    @contextmanager
    def timed(self, event: str, **fields: object) -> Iterator[dict[str, object]]:
        """Time a block and record its duration in milliseconds."""
        extra: dict[str, object] = {}
        started = time.perf_counter()
        try:
            yield extra
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
            self.write(event, duration_ms=duration_ms, **fields, **extra)


def read_trace(path: Path) -> Sequence[dict[str, Any]]:
    """Parse a trace file back into records."""
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
