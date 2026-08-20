"""Command entry points and the single place exceptions become exit codes."""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any, Final

import typer
from rich.console import Console
from rich.table import Table

from caudit import __version__
from caudit.config.loader import Config, ResolvedConfig, load_config_with_sources
from caudit.config.toolchain import ToolchainProbe
from caudit.errors import CauditError, UsageError
from caudit.logging import configure_logging, get_logger
from caudit.status import ExitCode

__all__ = ["COMMAND_EXIT_CODES", "app", "main"]

log = get_logger(__name__)

app = typer.Typer(
    name="caudit",
    help="Compiler-aware, evidence-gated auditing for C and C++.",
    add_completion=False,
    no_args_is_help=False,
    pretty_exceptions_enable=False,
)

#: Which exit codes each command can produce. T-01-11 asserts this covers
#: every ExitCode member, so a new code cannot be added without a caller.
COMMAND_EXIT_CODES: Final[dict[str, frozenset[ExitCode]]] = {
    "caudit": frozenset({ExitCode.OK, ExitCode.USAGE, ExitCode.INTERNAL}),
    "doctor": frozenset({ExitCode.OK, ExitCode.ENVIRONMENT}),
    "scan": frozenset(
        {
            ExitCode.OK,
            ExitCode.FINDINGS,
            ExitCode.USAGE,
            ExitCode.ENVIRONMENT,
            ExitCode.INTERNAL,
        }
    ),
    "eval": frozenset({ExitCode.OK, ExitCode.FINDINGS, ExitCode.USAGE, ExitCode.ENVIRONMENT}),
    "compare": frozenset({ExitCode.OK, ExitCode.FINDINGS, ExitCode.USAGE}),
    "ablate": frozenset({ExitCode.OK, ExitCode.USAGE, ExitCode.ENVIRONMENT}),
    # FINDINGS when the labels are miscalibrated: the run completed and its
    # result is that the confidence labels do not mean what they say.
    "calibrate": frozenset({ExitCode.OK, ExitCode.FINDINGS, ExitCode.USAGE}),
    # ENVIRONMENT when no pair produced an outcome — every one was excluded,
    # which is a problem with the machine or the corpus, not a clean result.
    "pairs": frozenset({ExitCode.OK, ExitCode.FINDINGS, ExitCode.USAGE, ExitCode.ENVIRONMENT}),
}


def _console(err: bool = False) -> Console:
    # soft_wrap keeps golden output stable regardless of terminal width.
    #
    # markup is off because almost everything printed here is user-derived —
    # file paths, diagnostics, limitation kinds — and rich reads `[...]` as a
    # style tag it then deletes. That silently ate the `[parse_failed]` prefix
    # on every limitation line. Styling is applied through `style=` instead.
    return Console(stderr=err, soft_wrap=True, highlight=False, markup=False)


def _resolved(ctx: typer.Context) -> ResolvedConfig:
    obj = ctx.obj
    if not isinstance(obj, ResolvedConfig):  # pragma: no cover - callback always runs
        raise UsageError("configuration was not initialised")
    return obj


def _parse_set_options(pairs: Sequence[str]) -> dict[str, object]:
    overrides: dict[str, object] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key.strip():
            raise UsageError(
                f"--set expects KEY=VALUE, got '{pair}'",
                hint="Example: --set llvm_version=19 --set token_budget.per_candidate=8000",
            )
        overrides[key.strip()] = value
    return overrides


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    show_version: Annotated[
        bool, typer.Option("--version", help="Print the package version and exit.")
    ] = False,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", metavar="PATH", help="TOML configuration file."),
    ] = None,
    overrides: Annotated[
        list[str] | None,
        typer.Option("--set", metavar="KEY=VALUE", help="Override one configuration key."),
    ] = None,
    log_level: Annotated[
        str, typer.Option("--log-level", help="critical|error|warning|info|debug")
    ] = "warning",
    print_config: Annotated[
        bool, typer.Option("--print-config", help="Dump the effective configuration and exit.")
    ] = False,
) -> None:
    """Resolve configuration once, for every subcommand."""
    if show_version:
        _console().print(f"caudit {__version__}")
        raise typer.Exit(int(ExitCode.OK))

    level = logging.getLevelNamesMapping().get(log_level.strip().upper())
    if level is None:
        raise UsageError(f"unknown --log-level '{log_level}'")
    configure_logging(level)

    cli_overrides = _parse_set_options(overrides or [])
    ctx.obj = load_config_with_sources(cli_overrides, config_file, os.environ)

    if print_config:
        _print_config(ctx.obj)
        raise typer.Exit(int(ExitCode.OK))

    if ctx.invoked_subcommand is None:
        _console().print(ctx.get_help())
        raise typer.Exit(int(ExitCode.OK))


def _print_config(resolved: ResolvedConfig) -> None:
    table = Table(title="Effective configuration", show_lines=False)
    table.add_column("key")
    table.add_column("value")
    table.add_column("source")
    for key, value, source in resolved.render_rows():
        table.add_row(key, value, str(source))
    console = _console()
    console.print(table)
    if resolved.config_file is not None:
        console.print(f"config file: {resolved.config_file}")
    console.print(
        "Secrets are not configuration: GEMINI_API_KEY is read from the environment "
        "at call time and is never stored, dumped, or logged."
    )


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Report every required tool, its version, and whether it satisfies the pin."""
    config: Config = _resolved(ctx).config
    probe = ToolchainProbe(llvm_major=config.llvm_major)
    infos = probe.probe_defaults()

    table = Table(title=f"Toolchain (LLVM pin: major {config.llvm_major})")
    for column in ("tool", "path", "version", "status", "note"):
        table.add_column(column, overflow="fold")
    for info in infos:
        status = "ok" if info.satisfies_requirement else str(info.status)
        if not info.required and not info.satisfies_requirement:
            status = f"{status} (optional)"
        table.add_row(
            info.name,
            str(info.path) if info.path else "-",
            info.version_display,
            status,
            info.detail,
        )

    console = _console()
    console.print(table)

    unsatisfied = [i for i in infos if i.required and not i.satisfies_requirement]
    if not unsatisfied:
        console.print("All required tools satisfied.")
        raise typer.Exit(int(ExitCode.OK))

    console.print("\nMissing or unsupported components. Install them with:")
    for hint in dict.fromkeys(info.install_hint for info in unsatisfied):
        console.print(f"  {hint}")
    console.print("\nFull procedure: my_docs/guides/setup.md")
    raise typer.Exit(int(ExitCode.ENVIRONMENT))


@app.command()
def scan(
    ctx: typer.Context,
    repository: Annotated[Path, typer.Argument(help="Repository root to scan.")],
    compile_commands: Annotated[
        Path | None,
        typer.Option("--compile-commands", help="Path to compile_commands.json."),
    ] = None,
    out: Annotated[Path, typer.Option("--out", help="Output directory.")] = Path("caudit-report"),
    target: Annotated[
        list[str] | None,
        typer.Option("--target", help="Restrict the scan to these paths or directories."),
    ] = None,
    allow_partial_coverage: Annotated[
        bool,
        typer.Option(
            "--allow-partial-coverage",
            help="Proceed below the coverage floor, recording the gap as a limitation.",
        ),
    ] = False,
    consent_cloud: Annotated[
        bool,
        typer.Option(
            "--consent-cloud",
            help="Allow selected source regions to be sent to the configured model.",
        ),
    ] = False,
    remember_consent: Annotated[
        bool,
        typer.Option(
            "--remember-consent",
            help="Record cloud consent for this repository. Implies --consent-cloud.",
        ),
    ] = False,
    dry_run_prompts: Annotated[
        bool,
        typer.Option(
            "--dry-run-prompts",
            help="Write every prompt that would be sent to <out>/prompts, and send nothing.",
        ),
    ] = False,
) -> None:
    """Scan a repository. Requires a valid compilation database."""
    from caudit.application.scan import run_scan
    from caudit.cli.scan_cmd import apply_scan_overrides

    config = _resolved(ctx).config
    if not repository.is_dir():
        raise UsageError(f"repository path is not a directory: {repository}")
    if compile_commands is None:
        raise UsageError(
            "missing required option --compile-commands",
            hint=(
                "C Audit will not guess include paths or compiler flags. Generate a "
                "compilation database first:\n"
                "  cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON\n"
                "then pass --compile-commands build/compile_commands.json"
            ),
        )

    effective = apply_scan_overrides(
        config,
        targets=list(target or []),
        allow_partial_coverage=allow_partial_coverage,
        consent_cloud=consent_cloud or remember_consent,
    )
    result = run_scan(
        repository,
        compile_commands,
        effective,
        out=out,
        console=_console(),
        remember=remember_consent,
        dry_run_prompts=dry_run_prompts,
    )
    raise typer.Exit(int(result.exit_code))


@app.command(name="eval")
def eval_command(
    ctx: typer.Context,
    suite: Annotated[
        str, typer.Option("--suite", help="Benchmark suite: mini|castle|juliet.")
    ] = "mini",
    baseline: Annotated[
        bool, typer.Option("--baseline/--no-baseline", help="Run analyzers only, no LLM.")
    ] = True,
    out: Annotated[Path, typer.Option("--out", help="Directory for metrics and traces.")] = Path(
        "caudit-eval"
    ),
    case: Annotated[
        list[str] | None, typer.Option("--case", help="Restrict to these case ids.")
    ] = None,
    use_clang: Annotated[
        bool,
        typer.Option(
            "--use-clang/--recorded",
            help="Run the real analyzers, or replay each case's committed recording.",
        ),
    ] = False,
    baseline_metrics: Annotated[
        Path | None,
        typer.Option(
            "--baseline-metrics",
            help=(
                "Analyzer-only metrics JSON this run must beat. The "
                "baseline_floor gate needs it on an adjudicated run."
            ),
        ),
    ] = None,
) -> None:
    """Measure a benchmark suite and apply the spec's hard gates.

    ``--recorded`` is the default so the suite scores offline on a machine with
    no LLVM, which is what CI needs. It is not what a published number needs:
    a recording is a replay of what the analyzers said once, and only the mini
    suite ships them. Any result meant to be quoted comes from ``--use-clang``.
    """
    # Imported lazily so `caudit doctor` does not pay for the eval harness.
    from caudit.cli.eval_cmd import run_eval

    code = run_eval(
        config=_resolved(ctx).config,
        suite=suite,
        baseline=baseline,
        out_dir=out,
        case_ids=tuple(case or ()),
        console=_console(),
        use_clang=use_clang,
        baseline_metrics=baseline_metrics,
    )
    raise typer.Exit(int(code))


@app.command()
def ablate(
    ctx: typer.Context,
    suite: Annotated[
        str, typer.Option("--suite", help="Benchmark suite: mini|castle|juliet.")
    ] = "mini",
    out: Annotated[Path, typer.Option("--out", help="Directory for the ablation record.")] = Path(
        "caudit-ablation"
    ),
    case: Annotated[
        list[str] | None, typer.Option("--case", help="Restrict to these case ids.")
    ] = None,
    token_budget: Annotated[
        list[int] | None,
        typer.Option("--token-budget", help="Per-run token budget to try. Repeatable."),
    ] = None,
    caller_depth: Annotated[
        list[int] | None,
        typer.Option("--caller-depth", help="Caller expansion depth to try. Repeatable."),
    ] = None,
    callee_depth: Annotated[
        list[int] | None,
        typer.Option(
            "--callee-depth",
            help="Callee expansion depth to try (1-8). Repeatable.",
        ),
    ] = None,
    type_closure_depth: Annotated[
        list[int] | None,
        typer.Option("--type-closure-depth", help="Type closure depth to try (1-16). Repeatable."),
    ] = None,
    use_clang: Annotated[
        bool,
        typer.Option(
            "--use-clang/--recorded",
            help="Run the real analyzers, or replay each case's committed recording.",
        ),
    ] = False,
    consent_cloud: Annotated[
        bool,
        typer.Option(
            "--consent-cloud",
            help="Adjudicate each configuration. Without it the grid measures retrieval only.",
        ),
    ] = False,
) -> None:
    """Run the retrieval and budget ablations, including the flat-window control.

    The control is in every grid whether or not it was asked for: it is the
    only configuration that tests whether compiler-aware retrieval is worth its
    complexity, and leaving it out is the easiest way to produce a flattering
    table.

    ``--recorded`` is the default, for the same reason it is on ``eval``: CI
    scores offline. Only the mini suite ships recordings, so a grid over any
    other corpus needs ``--use-clang`` -- and says so rather than scoring a
    corpus it has no candidates for.
    """
    from caudit.cli.ablate_cmd import run_ablation

    code = run_ablation(
        config=_resolved(ctx).config,
        suite=suite,
        out_dir=out,
        case_ids=tuple(case or ()),
        token_budgets=tuple(token_budget or ()),
        caller_depths=tuple(caller_depth or ()),
        callee_depths=tuple(callee_depth or ()),
        type_closure_depths=tuple(type_closure_depth or ()),
        consent_cloud=consent_cloud,
        console=_console(),
        use_clang=use_clang,
    )
    raise typer.Exit(int(code))


@app.command()
def calibrate(
    ctx: typer.Context,
    suite: Annotated[
        str, typer.Option("--suite", help="Benchmark suite: mini|castle|juliet.")
    ] = "mini",
    out: Annotated[
        Path, typer.Option("--out", help="Directory for the calibration record.")
    ] = Path("caudit-calibration"),
    case: Annotated[
        list[str] | None, typer.Option("--case", help="Restrict to these case ids.")
    ] = None,
    minimum_per_bin: Annotated[
        int,
        typer.Option("--minimum-per-bin", help="Bin size below which nothing is judged."),
    ] = 5,
) -> None:
    """Check confidence labels against ground truth.

    If `high` findings turn out true less often than `medium` ones, the labels
    are decoration and the run says so. Bins smaller than --minimum-per-bin are
    reported and not judged: a check that fires on noise is one somebody
    switches off.
    """
    from caudit.cli.calibrate_cmd import run_calibrate

    code = run_calibrate(
        config=_resolved(ctx).config,
        suite=suite,
        out_dir=out,
        case_ids=tuple(case or ()),
        console=_console(),
        minimum_per_bin=minimum_per_bin,
    )
    raise typer.Exit(int(code))


@app.command()
def pairs(
    ctx: typer.Context,
    manifest: Annotated[Path, typer.Option("--manifest", help="Pinned pair corpus.")] = Path(
        "benchmarks/pairs/manifest.yaml"
    ),
    held_out: Annotated[
        bool,
        typer.Option(
            "--held-out/--development",
            help="Run the held-out set. Every access is recorded and warned on.",
        ),
    ] = False,
    workspace: Annotated[
        Path, typer.Option("--workspace", help="Where checkouts, builds and reports go.")
    ] = Path("caudit-pairs"),
) -> None:
    """Scan pinned vulnerable/fixed repository pairs.

    A pair that cannot be checked out or built is excluded with its reason and
    counted in neither ratio: a corpus that quietly loses its hard cases
    reports a rising score for a falling tool.
    """
    from caudit.cli.pairs_cmd import run_pair_suite
    from caudit.eval.pairs import PairSet

    code = run_pair_suite(
        config=_resolved(ctx).config,
        manifest_path=manifest,
        pair_set=PairSet.HELD_OUT if held_out else PairSet.DEVELOPMENT,
        workspace=workspace,
        console=_console(),
    )
    raise typer.Exit(int(code))


@app.command()
def compare(
    ctx: typer.Context,
    baseline: Annotated[Path, typer.Argument(help="Analyzer-only baseline metrics report (JSON).")],
    adjudicated: Annotated[Path, typer.Argument(help="Adjudicated metrics report (JSON).")],
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Write the comparison to this file as JSON."),
    ] = None,
) -> None:
    """Compare an analyzer baseline with an adjudicated run.

    Every delta is adjudicated minus baseline, so the argument order decides
    the sign. Refuses two runs scored under different matching, prompt, or
    profile versions, or over different cases.
    """
    from caudit.cli.compare import run_compare

    _resolved(ctx)
    code = run_compare(baseline, adjudicated, console=_console(), out=out)
    raise typer.Exit(int(code))


def _handle_error(exc: CauditError) -> int:
    _console(err=True).print(f"error: {exc.render()}")
    return int(exc.exit_code)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and translate every outcome into an exit code.

    Typer vendors its own copy of click, so this deliberately catches only
    ``SystemExit`` (what the vendored layer raises for its own errors) plus
    our typed errors. Importing click directly would bind us to a package
    that is no longer a dependency.
    """
    # get_command avoids Typer.__call__, which installs a global excepthook.
    command: Any = typer.main.get_command(app)
    try:
        command(
            args=list(argv) if argv is not None else None,
            prog_name="caudit",
            standalone_mode=True,
        )
    except CauditError as exc:
        return _handle_error(exc)
    except SystemExit as exc:
        if exc.code is None:
            return int(ExitCode.OK)
        return exc.code if isinstance(exc.code, int) else int(ExitCode.USAGE)
    except Exception as exc:
        trace_id = uuid.uuid4().hex[:12]
        # The traceback goes to the log only at DEBUG; the user gets an id.
        if log.isEnabledFor(logging.DEBUG):
            log.exception("unhandled exception (trace id %s)", trace_id)
        else:
            log.error("unhandled %s (trace id %s)", type(exc).__name__, trace_id)
        _console(err=True).print(
            f"error: internal failure. Trace id: {trace_id}\n"
            "Re-run with --log-level debug to see the full traceback."
        )
        return int(ExitCode.INTERNAL)
    return int(ExitCode.OK)
