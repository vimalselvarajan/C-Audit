"""Worker pool tests: the timeout that has to actually stop a parse.

The parse functions here are module-level because the pool pickles them by
name to reach a spawned process. They stand in for libclang so the pool's own
behaviour — deadlines, replacement, ordering — is tested without depending on
how long a real parse happens to take.
"""

from __future__ import annotations

import multiprocessing
import os
import time
from pathlib import Path, PurePosixPath

import pytest

from caudit.index.parser import ParseRequest, ParseResult, ParseStatus
from caudit.index.workers import resolve_jobs, run_parallel, run_serial, worker_main
from caudit.model.finding import LimitationKind


def request_for(name: str) -> ParseRequest:
    return ParseRequest(
        file=PurePosixPath(name),
        repo_root=Path("/repo"),
        directory=Path("/repo"),
        arguments=("clang", "-c", name),
        language="c",
    )


def echo(request: ParseRequest) -> ParseResult:
    """A parse that succeeds instantly."""
    return ParseResult(file=request.file, status=ParseStatus.PARSED)


def sleep_for_slow(request: ParseRequest) -> ParseResult:
    """Never returns for `slow.c`; instant for everything else."""
    if request.file.name == "slow.c":
        time.sleep(120)
    return ParseResult(file=request.file, status=ParseStatus.PARSED)


def raise_for_bad(request: ParseRequest) -> ParseResult:
    if request.file.name == "bad.c":
        raise RuntimeError("libclang fell over")
    return ParseResult(file=request.file, status=ParseStatus.PARSED)


def exit_for_fatal(request: ParseRequest) -> ParseResult:
    """Kills its own worker, the way a segfault in libclang would."""
    if request.file.name == "fatal.c":
        os._exit(9)
    return ParseResult(file=request.file, status=ParseStatus.PARSED)


# ----------------------------------------------------------------- the worker


def test_the_worker_loop_answers_jobs_and_stops_on_the_sentinel() -> None:
    """Exercised in this process, so the loop that runs in the child is covered."""
    context = multiprocessing.get_context("spawn")
    job_receive, job_send = context.Pipe(duplex=False)
    result_receive, result_send = context.Pipe(duplex=False)

    job_send.send((0, request_for("a.c")))
    job_send.send(None)
    worker_main(job_receive, result_send, echo)

    position, result = result_receive.recv()
    assert (position, result.status) == (0, ParseStatus.PARSED)
    assert not result_receive.poll(), "the sentinel produced no result"


def test_the_worker_reports_a_crash_instead_of_dying_with_it() -> None:
    context = multiprocessing.get_context("spawn")
    job_receive, job_send = context.Pipe(duplex=False)
    result_receive, result_send = context.Pipe(duplex=False)

    job_send.send((0, request_for("bad.c")))
    job_send.send(None)
    worker_main(job_receive, result_send, raise_for_bad)

    _position, result = result_receive.recv()
    assert result.status is ParseStatus.CRASHED
    assert "libclang fell over" in result.limitations[0].detail
    assert result.limitations[0].affects == "bad.c"


# ------------------------------------------------------------------- the pool


def test_a_unit_past_its_deadline_is_stopped_and_the_rest_complete() -> None:
    """The requirement the whole module exists for.

    `slow.c` would run for two minutes. The pool stops it at one second,
    records the limitation, and the other two units still come back.
    """
    requests = [request_for(name) for name in ("a.c", "slow.c", "b.c")]
    started = time.monotonic()
    results = run_parallel(requests, jobs=3, timeout=1.0, execute=sleep_for_slow)
    elapsed = time.monotonic() - started

    assert [result.status for result in results] == [
        ParseStatus.PARSED,
        ParseStatus.TIMED_OUT,
        ParseStatus.PARSED,
    ]
    assert elapsed < 60, "the pool did not wait for the runaway parse"
    timed_out = results[1]
    assert timed_out.limitations[0].kind is LimitationKind.PARSE_FAILED
    assert "still parsing after 1s" in timed_out.limitations[0].detail
    assert timed_out.limitations[0].affects == "slow.c"


def test_a_worker_that_dies_is_reported_and_replaced() -> None:
    """A segfault in one unit must not take the run with it."""
    requests = [request_for(name) for name in ("a.c", "fatal.c", "b.c")]
    results = run_parallel(requests, jobs=2, timeout=30.0, execute=exit_for_fatal)

    by_file = {str(result.file): result for result in results}
    assert by_file["fatal.c"].status is ParseStatus.CRASHED
    assert "exited with code" in by_file["fatal.c"].limitations[0].detail
    assert by_file["a.c"].status is ParseStatus.PARSED
    assert by_file["b.c"].status is ParseStatus.PARSED


def test_results_come_back_in_request_order() -> None:
    """Whichever worker finishes first, the index must not notice."""
    requests = [request_for(f"{index:02d}.c") for index in range(8)]
    results = run_parallel(requests, jobs=4, timeout=30.0, execute=echo)
    assert [str(result.file) for result in results] == [str(item.file) for item in requests]


def test_an_exception_in_one_unit_does_not_stop_the_others() -> None:
    requests = [request_for(name) for name in ("a.c", "bad.c")]
    results = run_parallel(requests, jobs=2, timeout=30.0, execute=raise_for_bad)
    assert [result.status for result in results] == [ParseStatus.PARSED, ParseStatus.CRASHED]


def test_no_requests_needs_no_workers() -> None:
    assert run_parallel([], jobs=4, timeout=1.0, execute=echo) == []


def test_a_single_unit_is_parsed_in_process() -> None:
    """A worker would cost more than the parse, so one unit stays here."""
    results = run_parallel([request_for("a.c")], jobs=4, timeout=1.0, execute=echo)
    assert [result.status for result in results] == [ParseStatus.PARSED]


def test_serial_parsing_keeps_order() -> None:
    requests = [request_for(name) for name in ("b.c", "a.c")]
    assert [str(item.file) for item in run_serial(requests, echo)] == ["b.c", "a.c"]


@pytest.mark.parametrize(
    ("jobs", "units", "expected"),
    [(0, 1, 1), (4, 2, 2), (2, 8, 2), (1, 8, 1)],
)
def test_job_resolution(jobs: int, units: int, expected: int) -> None:
    assert resolve_jobs(jobs, units) == expected


def test_auto_jobs_never_exceeds_the_cpu_count() -> None:
    assert resolve_jobs(0, 1000) <= (os.cpu_count() or 1)
