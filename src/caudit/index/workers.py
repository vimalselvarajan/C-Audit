"""Parsing translation units in parallel, with a timeout that actually stops.

A seventh module beyond the six the plan names, because the alternative was
burying process management inside :mod:`caudit.index.parser`, where it would
obscure the libclang semantics that module exists to express.

The design is dictated by one requirement: *a per-TU timeout is a limitation,
not a silent skip*. That rules out the obvious implementations.

* A thread pool cannot enforce it. ``libclang`` parses inside a C call, so a
  Python-level timeout can only stop *waiting* for the parse — the thread runs
  on, and the interpreter joins it at exit, hanging the whole run.
* ``ProcessPoolExecutor`` cannot enforce it either. ``future.result(timeout=)``
  gives up on the result while the worker keeps parsing, and 3.12 has no
  supported way to kill that worker.

So the pool here owns its workers: one **private pipe pair per worker**, the
parent assigning jobs and watching deadlines, and a worker past its deadline
terminated and replaced. Private pipes rather than one shared queue because
killing a process mid-``put`` on a shared queue can leave the queue's lock
held forever — the failure this code exists to avoid would take the run down
with it.

Workers are started with the ``spawn`` context. ``fork`` would be cheaper, but
libclang runs each parse on its own thread, so the parent is multi-threaded by
the time a second unit is dispatched, and forking from a multi-threaded
process is deprecated in 3.12 and deadlock-prone in every version.
"""

from __future__ import annotations

import multiprocessing
import os
import time
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from multiprocessing.connection import Connection, wait
from multiprocessing.context import SpawnProcess
from typing import Any

from caudit.index import limits
from caudit.index.parser import ParseRequest, ParseResult, ParseStatus, parse_request
from caudit.logging import get_logger

__all__ = ["Execute", "run_parallel", "run_serial", "worker_main"]

log = get_logger(__name__)

#: A parse function. Must be importable by name: it is pickled to the worker.
Execute = Callable[[ParseRequest], ParseResult]

#: How long the parent blocks on one worker before looking at the others.
_POLL_SECONDS = 0.05

#: Grace period between ``terminate`` and ``kill`` for a worker that overran.
_TERMINATE_GRACE = 2.0


def run_serial(
    requests: Sequence[ParseRequest], execute: Execute = parse_request
) -> list[ParseResult]:
    """Parse in this process, in order.

    No timeout is enforced here and none is pretended: nothing in this process
    can interrupt a libclang call. Used for a single unit, where a worker would
    cost more than the parse, and when ``index.in_process`` is set for
    debugging.
    """
    return [execute(request) for request in requests]


def worker_main(jobs: Connection, results: Connection, execute: Execute) -> None:
    """The worker loop. Runs in the child; also called directly by its tests.

    Exceptions never escape: a crash on one unit is that unit's limitation, and
    a worker that died with a traceback tells the user less than a result that
    names the file.
    """
    while True:
        try:
            payload = jobs.recv()
        except EOFError:  # pragma: no cover - parent vanished
            return
        if payload is None:
            return
        position, request = payload
        try:
            result = execute(request)
        except BaseException as exc:
            # Deliberately broad: this is a process boundary. Whatever went
            # wrong becomes that unit's limitation instead of a dead worker.
            result = _crashed(request, f"{type(exc).__name__}: {exc}")
        results.send((position, result))


@dataclass
class _Worker:
    """One live process and the private pipes the parent talks to it through."""

    process: SpawnProcess
    jobs: Connection
    results: Connection
    position: int | None = None
    request: ParseRequest | None = None
    started_at: float = 0.0

    @property
    def idle(self) -> bool:
        return self.position is None

    def elapsed(self, now: float) -> float:
        return now - self.started_at

    def close(self) -> None:
        for connection in (self.jobs, self.results):
            with suppress(OSError):
                connection.close()


@dataclass
class _Pool:
    """Parent-side bookkeeping for a run."""

    context: Any
    execute: Execute
    timeout: float
    workers: list[_Worker] = field(default_factory=list)

    def spawn(self) -> _Worker:
        job_receive, job_send = self.context.Pipe(duplex=False)
        result_receive, result_send = self.context.Pipe(duplex=False)
        process = self.context.Process(
            target=worker_main,
            args=(job_receive, result_send, self.execute),
            daemon=True,
        )
        process.start()
        # The parent keeps only its own ends; leaving the child's ends open
        # here would stop EOF from ever reaching the worker.
        job_receive.close()
        result_send.close()
        worker = _Worker(process=process, jobs=job_send, results=result_receive)
        self.workers.append(worker)
        return worker

    def replace(self, worker: _Worker) -> _Worker:
        """Kill a worker and stand up a fresh one in its place."""
        _terminate(worker.process)
        worker.close()
        self.workers.remove(worker)
        return self.spawn()

    def shutdown(self) -> None:
        for worker in list(self.workers):
            # A worker that already exited is not an error here.
            with suppress(OSError):
                worker.jobs.send(None)
        for worker in list(self.workers):
            worker.process.join(timeout=_TERMINATE_GRACE)
            if worker.process.is_alive():  # pragma: no cover - stubborn worker
                _terminate(worker.process)
            worker.close()
        self.workers.clear()


def run_parallel(
    requests: Sequence[ParseRequest],
    *,
    jobs: int = 0,
    timeout: float = 120.0,
    execute: Execute = parse_request,
) -> list[ParseResult]:
    """Parse every request, in worker processes, honouring ``timeout`` per unit.

    Results come back in request order regardless of which worker finished
    first, so the index does not depend on scheduling. A unit that overruns
    yields a ``TIMED_OUT`` result carrying a limitation that names the file;
    a worker that dies yields ``CRASHED``, likewise named. Neither aborts the
    other units.
    """
    if not requests:
        return []
    worker_count = resolve_jobs(jobs, len(requests))
    if worker_count <= 1:
        return run_serial(requests, execute)

    pool = _Pool(context=multiprocessing.get_context("spawn"), execute=execute, timeout=timeout)
    collected: dict[int, ParseResult] = {}
    pending = list(enumerate(requests))
    pending.reverse()  # popped from the end, so dispatch follows request order
    try:
        for _ in range(worker_count):
            pool.spawn()
        while len(collected) < len(requests):
            _dispatch(pool, pending)
            _collect(pool, collected)
            _enforce_deadlines(pool, collected)
    finally:
        pool.shutdown()
    return [collected[position] for position in sorted(collected)]


def resolve_jobs(jobs: int, units: int) -> int:
    """``0`` means one worker per CPU, never more than there are units."""
    if jobs > 0:
        return min(jobs, units)
    return max(1, min(os.cpu_count() or 1, units))


def _dispatch(pool: _Pool, pending: list[tuple[int, ParseRequest]]) -> None:
    for worker in pool.workers:
        if not pending:
            return
        if not worker.idle:
            continue
        position, request = pending.pop()
        worker.position = position
        worker.request = request
        worker.started_at = time.monotonic()
        try:
            worker.jobs.send((position, request))
        except (BrokenPipeError, OSError):  # pragma: no cover - dead on arrival
            pending.append((position, request))
            worker.position = None
            worker.request = None


def _collect(pool: _Pool, collected: dict[int, ParseResult]) -> None:
    """Drain whatever is ready, blocking briefly so the loop does not spin."""
    busy = [worker for worker in pool.workers if not worker.idle]
    if not busy:
        return
    ready = wait([worker.results for worker in busy], timeout=_POLL_SECONDS)
    for connection in ready:
        worker = next(item for item in busy if item.results is connection)
        try:
            position, result = worker.results.recv()
        except (EOFError, OSError):  # pragma: no cover - handled as a crash below
            continue
        collected[position] = result
        worker.position = None
        worker.request = None


def _enforce_deadlines(pool: _Pool, collected: dict[int, ParseResult]) -> None:
    """Stop any worker past its ceiling, and replace one that died."""
    now = time.monotonic()
    for worker in list(pool.workers):
        if worker.idle or worker.request is None or worker.position is None:
            continue
        if worker.elapsed(now) > pool.timeout:
            log.warning(
                "parse of %s exceeded %.1fs; stopping it", worker.request.file, pool.timeout
            )
            collected[worker.position] = _timed_out(worker.request, pool.timeout)
            pool.replace(worker)
        elif not worker.process.is_alive():
            collected[worker.position] = _crashed(
                worker.request, f"worker exited with code {worker.process.exitcode}"
            )
            pool.replace(worker)


def _terminate(process: SpawnProcess) -> None:
    process.terminate()
    process.join(timeout=_TERMINATE_GRACE)
    if process.is_alive():  # pragma: no cover - SIGTERM is normally enough
        process.kill()
        process.join(timeout=_TERMINATE_GRACE)


def _timed_out(request: ParseRequest, seconds: float) -> ParseResult:
    return ParseResult(
        file=request.file,
        status=ParseStatus.TIMED_OUT,
        limitations=[limits.parse_timed_out(request.file, seconds)],
    )


def _crashed(request: ParseRequest, detail: str) -> ParseResult:
    return ParseResult(
        file=request.file,
        status=ParseStatus.CRASHED,
        limitations=[limits.parse_failed(request.file, detail)],
    )
