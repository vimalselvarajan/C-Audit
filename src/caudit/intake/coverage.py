"""Coverage accounting, and the decision the spec calls "materially incomplete".

The spec requires stopping when the compilation database is materially
incomplete. That phrase needs a number, not a judgement call, or every run
argues with itself about whether to proceed. The number is
``intake.coverage_floor`` (default 0.60), and it is an admitted guess: it is
configurable, printed in every stop message, and revisited against real
repositories in part 13.

Coverage is reported, not smoothed. The counts here flow into the report
verbatim so a reader can see what was never looked at — which is the only
thing that makes a low finding count meaningful.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import Final

from caudit.config.loader import IntakeConfig
from caudit.errors import IntakeError
from caudit.intake.compdb import iter_source_files, setup_recipe
from caudit.intake.filters import ExclusionRules, has_generated_banner, is_generated_name
from caudit.intake.plan import Coverage, ExclusionReason, compute_ratio
from caudit.model.finding import Limitation, LimitationKind

__all__ = [
    "FLOOR_EPSILON",
    "build_coverage",
    "check_completeness",
    "count_source_files",
]

#: The floor comparison is inclusive: a ratio *at* the floor proceeds. The
#: epsilon absorbs binary-float representation so ``0.6 >= 0.6`` cannot fail
#: for a repository whose numbers happen to divide badly.
FLOOR_EPSILON: Final[float] = 1e-9

#: How many uncovered files a limitation names before it says "and N more".
_MAX_NAMED_FILES: Final[int] = 10


def count_source_files(repo_root: Path, rules: ExclusionRules) -> list[PurePosixPath]:
    """In-scope implementation files present under ``repo_root``.

    Headers are excluded: they have no entry of their own and are reached
    through the units that include them, so counting them would make every
    honest C project look half-uncovered.

    Vendored and generated files are excluded too — from the denominator as
    well as the numerator. A repository that vendors a large dependency should
    not be told its own build description is incomplete.
    """
    present: list[PurePosixPath] = []
    for absolute in iter_source_files(repo_root, rules.skip_directories()):
        relative = PurePosixPath(absolute.relative_to(repo_root).as_posix())
        if not rules.include_third_party and rules.is_vendored(relative):
            continue
        if not rules.include_generated and (
            is_generated_name(relative) or has_generated_banner(absolute)
        ):
            continue
        present.append(relative)
    return sorted(present, key=str)


def build_coverage(
    *,
    entries_in_database: int,
    selected: int,
    exclusions: Iterable[ExclusionReason],
    files_present: Sequence[PurePosixPath],
    files_in_database: Iterable[PurePosixPath],
) -> Coverage:
    """Assemble the counts.

    ``files_in_database`` is every path the database mentions, *before*
    ``--target`` narrowing. Coverage measures whether the build description
    covers the tree; deciding to scan only part of it is a separate question,
    and conflating them would make an intentional ``--target`` look like a
    broken build.
    """
    counts = Counter(exclusions)
    mentioned = set(files_in_database)
    present = list(files_present)
    covered = sum(1 for path in present if path in mentioned)
    return Coverage(
        tus_in_database=entries_in_database,
        tus_selected=selected,
        tus_excluded={reason: counts[reason] for reason in ExclusionReason if counts[reason]},
        source_files_in_tree=len(present),
        source_files_covered=covered,
        coverage_ratio=compute_ratio(covered, len(present)),
    )


def uncovered_files(
    files_present: Sequence[PurePosixPath], files_in_database: Iterable[PurePosixPath]
) -> list[PurePosixPath]:
    mentioned = set(files_in_database)
    return [path for path in files_present if path not in mentioned]


def check_completeness(
    coverage: Coverage,
    config: IntakeConfig,
    *,
    compdb_path: Path,
    uncovered: Sequence[PurePosixPath] = (),
) -> Limitation | None:
    """Stop, or record a limitation, or say nothing.

    * Below the floor and no opt-in → :class:`IntakeError`, exit ``ENVIRONMENT``.
    * Below the floor with ``--allow-partial-coverage`` → a recorded limitation.
    * Between the floor and 1.0 → a recorded limitation.
    * Complete → ``None``.
    """
    ratio = coverage.coverage_ratio
    floor = config.coverage_floor

    if ratio + FLOOR_EPSILON < floor:
        if not config.allow_partial_coverage:
            raise IntakeError(
                f"the compilation database covers {ratio:.2f} of the repository's source "
                f"files ({coverage.source_files_covered} of {coverage.source_files_in_tree}), "
                f"below the required floor of {floor:.2f}",
                hint=(
                    f"{_name_files(uncovered)}\n\n"
                    "Either rebuild so every target is described:\n\n"
                    f"{setup_recipe(compdb_path)}\n\n"
                    "or accept the gap deliberately with --allow-partial-coverage, which "
                    "records it in the report instead of stopping. The floor itself is "
                    "configurable as intake.coverage_floor."
                ),
            )
        return Limitation(
            kind=LimitationKind.MISSING_BUILD_TARGET,
            detail=(
                f"scanned with --allow-partial-coverage at {ratio:.2f} coverage, below the "
                f"{floor:.2f} floor: {coverage.source_files_covered} of "
                f"{coverage.source_files_in_tree} source files are described by the build. "
                f"Absence of findings in the remainder is not evidence of their absence."
            ),
            affects=_affects(uncovered),
        )

    if coverage.is_complete:
        return None

    return Limitation(
        kind=LimitationKind.MISSING_BUILD_TARGET,
        detail=(
            f"{coverage.source_files_in_tree - coverage.source_files_covered} of "
            f"{coverage.source_files_in_tree} source files are not described by the "
            f"compilation database ({ratio:.2f} coverage) and were not analysed"
        ),
        affects=_affects(uncovered),
    )


def _name_files(paths: Sequence[PurePosixPath]) -> str:
    if not paths:
        return "No source files were matched to a build entry."
    shown = [str(path) for path in paths[:_MAX_NAMED_FILES]]
    remainder = len(paths) - len(shown)
    listing = "\n".join(f"  {name}" for name in shown)
    if remainder > 0:
        listing += f"\n  ... and {remainder} more"
    return "Source files with no entry in the compilation database:\n" + listing


def _affects(paths: Sequence[PurePosixPath]) -> str | None:
    if not paths:
        return None
    shown = ", ".join(str(path) for path in paths[:_MAX_NAMED_FILES])
    remainder = len(paths) - min(len(paths), _MAX_NAMED_FILES)
    return f"{shown} (and {remainder} more)" if remainder else shown
