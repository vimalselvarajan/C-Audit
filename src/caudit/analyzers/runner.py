"""Running analyzers as subprocesses: argv, timeouts, capture, limitations.

One rule shapes this module: **a crashed, timed-out, or refused analyzer is a
recorded blind spot, never an empty result.** "We found nothing" and "we did
not look" produce identical candidate lists and completely different reports,
so every way a run can end badly gets a :class:`~caudit.model.finding.Limitation`
naming the analyzer and the translation unit, and the other units carry on.

Concurrency is a thread pool rather than part 06's process pool. The work is
in a child process, not in this interpreter, so a thread blocked on
``subprocess.run`` costs nothing and ``timeout=`` genuinely stops the child —
which is exactly what libclang's in-process parse could not do.

Argument handling stays inside the promise part 05 makes. The build's own argv
is used verbatim minus its compilation-only flags; the profile's analysis
flags are added for the analyzer's benefit and never written back into the
build; and no include path, macro, or language standard is ever invented.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, Protocol

from pydantic import BaseModel, ConfigDict, Field

from caudit.index.workers import resolve_jobs
from caudit.intake.plan import TranslationUnit
from caudit.logging import get_logger
from caudit.model.candidate import Candidate
from caudit.model.evidence import Producer
from caudit.model.finding import Limitation, LimitationKind

__all__ = [
    "Analyzer",
    "AnalyzerRun",
    "CommandResult",
    "RunRequest",
    "RunStatus",
    "Subprocess",
    "analysis_flags",
    "analyzer_failed",
    "run_command",
    "run_units",
    "source_argument",
    "tool_unavailable",
    "warnings_stay_warnings",
]

log = get_logger(__name__)

_SOURCE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"}
)

#: Shells and runtimes report a fatal signal as 128 + signal number. Treating
#: that as an ordinary non-zero exit would file an abort under the same heading
#: as "the tool found errors", which are different failures.
_SIGNAL_EXIT_FLOOR: Final = 128


class RunStatus(StrEnum):
    """How one analyzer invocation ended."""

    OK = "ok"
    #: The tool ran and exited non-zero. Its output is still parsed: clang-tidy
    #: exits non-zero on a compile error and still reports what it saw.
    NONZERO_EXIT = "nonzero_exit"
    TIMED_OUT = "timed_out"
    #: Killed by a signal, or the process could not be started at all.
    CRASHED = "crashed"
    #: The binary is not on PATH. Distinct from a crash: nothing ran.
    TOOL_MISSING = "tool_missing"

    @property
    def is_failure(self) -> bool:
        return self is not RunStatus.OK

    @property
    def produced_output(self) -> bool:
        """Whether parsing what the tool wrote is still worthwhile."""
        return self in (RunStatus.OK, RunStatus.NONZERO_EXIT)


@dataclass(frozen=True)
class CommandResult:
    """One completed subprocess, with stdout and stderr already merged."""

    status: RunStatus
    exit_code: int
    output: str
    duration_s: float
    detail: str = ""

    @property
    def status_is_failure(self) -> bool:
        return self.status.is_failure


#: A subprocess runner: ``(command, cwd, timeout_s) -> CommandResult``.
#: Injected by tests so the default suite never shells out to a compiler.
Subprocess = Callable[[Sequence[str], Path | None, float], CommandResult]


def run_command(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout_s: float = 300.0,
    subprocess_runner: Subprocess | None = None,
) -> CommandResult:
    """Run one command, capturing everything and classifying how it ended."""
    if subprocess_runner is not None:
        return subprocess_runner(list(command), cwd, timeout_s)
    return _run_subprocess(list(command), cwd, timeout_s)


def _run_subprocess(command: list[str], cwd: Path | None, timeout_s: float) -> CommandResult:
    if not command or shutil.which(command[0]) is None:
        return CommandResult(
            status=RunStatus.TOOL_MISSING,
            exit_code=-1,
            output="",
            duration_s=0.0,
            detail=f"{command[0] if command else '<empty command>'} is not on PATH",
        )
    started = time.monotonic()
    try:
        # argv, never a shell string: nothing here is interpolated into a shell.
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as expired:
        return CommandResult(
            status=RunStatus.TIMED_OUT,
            exit_code=-1,
            output=_decode(expired.stdout) + _decode(expired.stderr),
            duration_s=time.monotonic() - started,
            detail=f"still running after {timeout_s:g}s and was stopped",
        )
    except OSError as exc:
        return CommandResult(
            status=RunStatus.CRASHED,
            exit_code=-1,
            output="",
            duration_s=time.monotonic() - started,
            detail=f"could not be executed: {exc}",
        )
    return CommandResult(
        status=_classify(completed.returncode),
        exit_code=completed.returncode,
        output=f"{completed.stdout}{completed.stderr}",
        duration_s=time.monotonic() - started,
        detail=_exit_detail(completed.returncode),
    )


def _classify(code: int) -> RunStatus:
    if code == 0:
        return RunStatus.OK
    if code < 0 or code >= _SIGNAL_EXIT_FLOOR:
        return RunStatus.CRASHED
    return RunStatus.NONZERO_EXIT


def _exit_detail(code: int) -> str:
    if code == 0:
        return ""
    if code < 0:
        return f"killed by signal {-code}"
    if code >= _SIGNAL_EXIT_FLOOR:
        return f"exited {code}, which is 128 + signal {code - _SIGNAL_EXIT_FLOOR}"
    return f"exited {code}"


def _decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else ""


# ------------------------------------------------------------------ arguments


def source_argument(unit: TranslationUnit) -> str:
    """The token in the build's argv that names the file being compiled.

    Returned exactly as the build spells it — relative or absolute — because
    the analyzer runs with ``unit.directory`` as its working directory, which
    is what makes a relative spelling resolve the way the build intends.
    """
    wanted = unit.file.name
    for argument in reversed(unit.arguments[1:]):
        if argument.startswith("-"):
            continue
        candidate = PurePosixPath(argument.replace("\\", "/"))
        if candidate.name == wanted and candidate.suffix.lower() in _SOURCE_SUFFIXES:
            return argument
    # A database that never names its own input. Fall back to the plan's path,
    # which is repository-relative and resolves under the repository root.
    return str(unit.file)


def analysis_flags(unit: TranslationUnit) -> list[str]:
    """The build's flags, minus argv[0], minus the input file.

    Nothing is added here. The caller appends the profile's analysis flags and
    the source file itself, so what came from the build and what C Audit chose
    stay distinguishable in the recorded command.
    """
    source = source_argument(unit)
    return [argument for argument in unit.parse_arguments[1:] if argument != source]


def warnings_stay_warnings() -> list[str]:
    """Undo the build's ``-Werror`` for the duration of the analysis.

    Emitted immediately after :func:`analysis_flags` and before the profile's
    own flags, so it overrides a ``-Werror`` that came from the build and
    nothing the profile deliberately asks for.

    **This is a correctness requirement, not a preference.** A project that
    compiles with ``-Werror`` -- libarchive, curl, git, systemd, most of them --
    promotes every diagnostic the curated profile adds into an error. Three
    things then go wrong at once, and only the first is cosmetic: the run exits
    non-zero; clang stops at ``-ferror-limit`` (20 by default), so a unit with
    21 findings reports 20 and silently drops the rest; and errors halt
    compilation, so everything after the limit -- including whatever the static
    analyzer would have walked -- is never examined at all. The result is a
    truncated analysis that looks like a complete one, on precisely the
    repositories the tool exists for.

    No synthetic corpus can show this. The mini suite's compile lines are
    written here and CASTLE's come from its own manifest as ``gcc <file> -o
    <bin>``; neither carries ``-Werror``, so this flag is a no-op on both and
    the profile version does not move. It was found by running the analyzers
    over a real repository for the first time.

    We are running the compiler to collect diagnostics, never to gate a build,
    so promoting them is never what this call wants.
    """
    return ["-Wno-error"]


# ---------------------------------------------------------------------- runs


class AnalyzerRun(BaseModel):
    """One analyzer, one translation unit, one recorded outcome.

    Beyond the fields the plan names, this carries ``status``, ``command``,
    ``log_path``, and ``detail``: an exit code alone cannot distinguish a
    timeout from a missing binary, and a report that cannot name the command
    that produced it is not reproducible.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    analyzer: Producer
    tool_name: str = Field(min_length=1)
    #: Verbatim, never inferred. Captured per run rather than per session: a
    #: repository can hit different toolchains in exotic setups.
    tool_version: str = Field(min_length=1)
    profile_version: str | None = None
    unit: PurePosixPath
    working_directory: Path
    exit_code: int
    duration_s: float = Field(ge=0.0)
    status: RunStatus
    command: list[str] = Field(min_length=1)
    #: The machine-readable artifact the parser reads. Retained for provenance,
    #: never fed to a prompt.
    raw_output_path: Path
    #: Console capture, kept beside the artifact so a confusing result can be
    #: traced back to what the tool actually said.
    log_path: Path | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is RunStatus.OK

    def read_raw_output(self) -> str:
        """The artifact's text, or ``""`` when the tool wrote nothing."""
        if not self.status.produced_output:
            return ""
        try:
            return self.raw_output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def limitation(self) -> Limitation | None:
        """The blind spot this run leaves behind, or ``None`` when it is clean."""
        if self.status is RunStatus.OK:
            return None
        if self.status is RunStatus.TOOL_MISSING:
            return tool_unavailable(self.tool_name, self.command[0], unit=self.unit)
        return analyzer_failed(self.tool_name, self.unit, self.status, self.detail)

    def describe(self) -> str:
        return f"{self.tool_name} on {self.unit}: {self.status.value}"


class RunRequest(BaseModel):
    """Everything one invocation needs, so the pool can stay dumb."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    analyzer: Producer
    tool_name: str
    tool_version: str
    profile_version: str | None
    unit: TranslationUnit
    command: list[str]
    raw_output_path: Path
    log_path: Path | None = None
    subprocess_runner: Subprocess | None = None

    def execute(self, timeout_s: float) -> AnalyzerRun:
        """Run it, persist what it wrote, and record how it ended."""
        self.raw_output_path.parent.mkdir(parents=True, exist_ok=True)
        result = run_command(
            self.command,
            cwd=self.unit.directory,
            timeout_s=timeout_s,
            subprocess_runner=self.subprocess_runner,
        )
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path.write_text(result.output, encoding="utf-8")
        if result.status.is_failure:
            log.warning(
                "%s on %s: %s (%s)",
                self.tool_name,
                self.unit.file,
                result.status.value,
                result.detail or "no detail",
            )
        return AnalyzerRun(
            analyzer=self.analyzer,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            profile_version=self.profile_version,
            unit=self.unit.file,
            working_directory=self.unit.directory,
            exit_code=result.exit_code,
            duration_s=result.duration_s,
            status=result.status,
            command=list(self.command),
            raw_output_path=self.raw_output_path,
            log_path=self.log_path,
            detail=result.detail,
        )


class Analyzer(Protocol):
    """What every analyzer implements.

    ``parse`` returns candidates rather than raw diagnostics because each
    analyzer owns the translation from its own format; normalization into the
    shared schema happens in one place, behind that call.
    """

    name: Producer
    tool_name: str
    tool_version: str

    def run(self, unit: TranslationUnit, timeout_s: float, *, out_dir: Path) -> AnalyzerRun: ...

    def parse(self, run: AnalyzerRun) -> list[Candidate]: ...


def run_units(
    analyzers: Sequence[Analyzer],
    units: Sequence[TranslationUnit],
    *,
    out_dir: Path,
    timeout_s: float,
    jobs: int = 0,
) -> list[AnalyzerRun]:
    """Run every analyzer over every unit, in parallel, in a fixed order.

    Results come back ordered by ``(unit, analyzer)`` regardless of which
    finished first. That is what makes the candidate list independent of
    completion order — a scheduler that happens to be faster on one machine
    must not change what a report says.
    """
    work = [(unit, analyzer) for unit in units for analyzer in analyzers]
    if not work:
        return []
    workers = resolve_jobs(jobs, len(work))
    if workers <= 1:
        return [analyzer.run(unit, timeout_s, out_dir=out_dir) for unit, analyzer in work]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="caudit-analyzer") as pool:
        futures = [
            pool.submit(analyzer.run, unit, timeout_s, out_dir=out_dir) for unit, analyzer in work
        ]
        return [future.result() for future in futures]


# --------------------------------------------------------------- limitations


def analyzer_failed(
    tool_name: str, unit: PurePosixPath | str, status: RunStatus, detail: str = ""
) -> Limitation:
    """An analyzer that did not finish on one unit. Not a clean unit."""
    reason = {
        RunStatus.TIMED_OUT: "was stopped at its timeout",
        RunStatus.CRASHED: "crashed",
        RunStatus.NONZERO_EXIT: "exited non-zero",
    }.get(status, "did not complete")
    suffix = f" ({detail})" if detail else ""
    return Limitation(
        kind=LimitationKind.ANALYZER_FAILED,
        detail=(
            f"{tool_name} {reason} on {unit}{suffix}; this translation unit was not "
            f"fully analysed by {tool_name}, so the absence of a {tool_name} candidate "
            "in it means nothing"
        ),
        affects=str(unit),
    )


def tool_unavailable(
    tool_name: str, binary: str, *, unit: PurePosixPath | str | None = None
) -> Limitation:
    """A required analyzer binary that is not installed."""
    where = f" for {unit}" if unit is not None else ""
    return Limitation(
        kind=LimitationKind.TOOLCHAIN_UNAVAILABLE,
        detail=(
            f"{tool_name} was not run{where}: '{binary}' is not on PATH. No candidate "
            f"from {tool_name} exists in this run, which is not the same as {tool_name} "
            "finding nothing. See my_docs/guides/setup.md"
        ),
        affects=str(unit) if unit is not None else None,
    )


def checkers_unavailable(tool_name: str, missing: Iterable[str]) -> Limitation:
    """Profile checkers the installed toolchain does not have."""
    names = ", ".join(sorted(missing))
    return Limitation(
        kind=LimitationKind.TOOLCHAIN_UNAVAILABLE,
        detail=(
            f"the check profile names {names}, which this {tool_name} does not "
            "provide; those checks did not run and nothing they would have found is "
            "in this report"
        ),
        affects=None,
    )
