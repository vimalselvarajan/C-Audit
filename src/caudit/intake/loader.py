"""`load_scan_plan` — turning a directory into a validated, pinned scan plan.

This is the one function the rest of the pipeline calls. Everything it can
determine, it determines here and once: the revision, the units, the
exclusions and their reasons, the coverage numbers, and the blind spots. What
it cannot determine, it refuses to invent.

Order matters. The revision is pinned before any file is read; the database is
validated before the tree is walked; the coverage decision is made before a
plan is returned. A caller therefore either gets a plan that is internally
consistent or gets an error explaining what to fix.
"""

from __future__ import annotations

import difflib
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from caudit.config.loader import Config
from caudit.errors import IntakeError
from caudit.intake.compdb import (
    RawEntry,
    is_header_file,
    language_of,
    load_entries,
    parse_std,
    standard_is_supported,
    std_argument,
)
from caudit.intake.coverage import (
    build_coverage,
    check_completeness,
    count_source_files,
    uncovered_files,
)
from caudit.intake.filters import ExclusionRules, TargetSelector
from caudit.intake.plan import (
    ExclusionReason,
    ScanPlan,
    TranslationUnit,
    sort_exclusions,
    sort_units,
)
from caudit.intake.revision import GitRunner, resolve_revision
from caudit.logging import get_logger
from caudit.model.finding import Limitation, LimitationKind

__all__ = ["load_scan_plan"]

log = get_logger(__name__)

#: How many colliding paths a single limitation names before it summarizes.
_MAX_NAMED = 10


def load_scan_plan(
    root: Path,
    compdb: Path,
    config: Config,
    *,
    git_runner: GitRunner | None = None,
) -> ScanPlan:
    """Validate the build description and decide what will be scanned.

    Raises :class:`~caudit.errors.IntakeError` (exit ``ENVIRONMENT``) when the
    database is absent or materially incomplete. Never infers flags.
    """
    repo_root = _resolve_root(root)
    intake = config.intake

    revision = (
        resolve_revision(repo_root, runner=git_runner)
        if git_runner is not None
        else resolve_revision(repo_root)
    )

    entries = load_entries(compdb, response_file_depth=intake.response_file_depth)
    database = _deduplicate(entries, repo_root)

    selector = TargetSelector(intake.targets)
    rules = ExclusionRules(
        selector=selector,
        include_third_party=intake.include_third_party,
        include_generated=intake.include_generated,
        user_globs=tuple(config.exclude_globs),
        max_file_bytes=config.token_budget.max_file_bytes,
    )

    _check_targets(selector, database.paths, compdb)

    units, excluded = _classify(database.units, repo_root, rules)

    limitations: list[Limitation] = []
    if revision.limitation is not None:
        limitations.append(revision.limitation)
    limitations.extend(database.limitations)
    limitations.extend(_exclusion_limitations(excluded))

    files_present = count_source_files(repo_root, rules)
    coverage = build_coverage(
        entries_in_database=database.entry_count,
        selected=len(units),
        exclusions=[
            *(reason for _, reason in excluded),
            *([ExclusionReason.NOT_SELECTED] * len(database.outside)),
        ],
        files_present=files_present,
        files_in_database=database.paths,
    )
    uncovered = uncovered_files(files_present, database.paths)
    gap = check_completeness(coverage, intake, compdb_path=compdb, uncovered=uncovered)
    if gap is not None:
        limitations.append(gap)

    overrides = rules.enabled_overrides()
    if intake.allow_partial_coverage:
        overrides.append("intake.allow_partial_coverage")

    plan = ScanPlan(
        repo_root=repo_root,
        revision=revision.revision,
        dirty=revision.dirty,
        compile_commands_path=compdb.resolve(),
        units=sort_units(units),
        excluded=sort_exclusions(excluded),
        coverage=coverage,
        limitations=_dedupe_limitations(limitations),
        overrides=overrides,
    )
    log.debug("scan plan at %s: %s", revision.describe(), coverage.describe())
    return plan


def _resolve_root(root: Path) -> Path:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise IntakeError(f"repository root is not a directory: {root}")
    return resolved


def _relative_to_root(absolute: Path, repo_root: Path) -> PurePosixPath | None:
    """Repository-relative POSIX path, or ``None`` when the file is outside."""
    try:
        return PurePosixPath(absolute.relative_to(repo_root).as_posix())
    except ValueError:
        return None


@dataclass(frozen=True)
class _Database:
    """The database after duplicate resolution, before any scoping decision."""

    #: Raw entry count, before deduplication.
    entry_count: int
    #: One entry per repository-relative file, sorted by path.
    units: list[tuple[PurePosixPath, RawEntry]]
    #: Entries compiling files outside the repository root. Counted, but with
    #: no repository-relative path they can never be cited, so they cannot be
    #: listed in ``ScanPlan.excluded``.
    outside: list[Path]
    limitations: list[Limitation]

    @property
    def paths(self) -> list[PurePosixPath]:
        return [path for path, _ in self.units]


def _deduplicate(entries: Iterable[RawEntry], repo_root: Path) -> _Database:
    """One entry per file: last one in the database wins.

    Multi-config builds legitimately compile the same file twice with
    different flags. Picking one is unavoidable; picking it *deterministically*
    is not, so the rule is positional — which makes the result independent of
    dict iteration order and stable across shuffles of equal input — and the
    discarded configurations are recorded rather than dropped in silence.
    """
    chosen: dict[PurePosixPath, RawEntry] = {}
    collisions: dict[PurePosixPath, list[RawEntry]] = defaultdict(list)
    outside: list[Path] = []
    count = 0

    for entry in entries:
        count += 1
        relative = _relative_to_root(entry.absolute_file, repo_root)
        if relative is None:
            outside.append(entry.absolute_file)
            continue
        previous = chosen.get(relative)
        if previous is None:
            chosen[relative] = entry
        elif entry.index >= previous.index:
            # Positional, not arrival order, so the winner does not depend on
            # how the entries reached this loop.
            collisions[relative].append(previous)
            chosen[relative] = entry
        else:
            collisions[relative].append(entry)

    limitations = [
        Limitation(
            kind=LimitationKind.AMBIGUOUS_BUILD_CONFIG,
            detail=(
                f"{path} is compiled {len(discarded) + 1} times with different commands; "
                f"the entry at position {chosen[path].index} was analysed and "
                f"{len(discarded)} other configuration(s) were not"
            ),
            affects=str(path),
        )
        for path, discarded in sorted(collisions.items(), key=lambda item: str(item[0]))
    ]
    if outside:
        limitations.append(_outside_limitation(outside))

    return _Database(
        entry_count=count,
        units=sorted(chosen.items(), key=lambda item: str(item[0])),
        outside=outside,
        limitations=limitations,
    )


def _check_targets(selector: TargetSelector, known: list[PurePosixPath], compdb: Path) -> None:
    """A ``--target`` that matches nothing is a typo, not an empty scan."""
    if not selector.active:
        return
    missed = selector.unmatched(known)
    if not missed:
        return
    lines: list[str] = []
    for target in missed:
        close = difflib.get_close_matches(target, [str(path) for path in known], n=3, cutoff=0.4)
        if close:
            lines.append(f"  {target} — nearest entries: " + ", ".join(close))
        else:
            lines.append(f"  {target} — no similar entry")
    raise IntakeError(
        f"--target matched no entry in {compdb}: " + ", ".join(missed),
        hint=(
            "\n".join(lines) + f"\n\nThe database describes {len(known)} file(s). Targets are "
            "repository-relative paths, or directory prefixes."
        ),
    )


def _classify(
    resolved: list[tuple[PurePosixPath, RawEntry]],
    repo_root: Path,
    rules: ExclusionRules,
) -> tuple[list[TranslationUnit], list[tuple[PurePosixPath, ExclusionReason]]]:
    """Split the deduplicated entries into selected units and excluded paths."""
    units: list[TranslationUnit] = []
    excluded: list[tuple[PurePosixPath, ExclusionReason]] = []

    for relative, entry in resolved:
        if is_header_file(relative):
            # A header with its own entry is a build artefact of some
            # generators. It is reached through its includers instead.
            excluded.append((relative, ExclusionReason.UNSUPPORTED_LANGUAGE))
            continue

        language = language_of(entry.arguments, str(relative))
        std_raw = std_argument(entry.arguments)
        std = parse_std(std_raw) if std_raw else None
        supported = language is not None and (std is None or standard_is_supported(std))

        reason = rules.reason_for(
            relative,
            real_path=repo_root / Path(*relative.parts),
            language_supported=supported,
        )
        if reason is not None:
            excluded.append((relative, reason))
            continue
        if language is None:  # pragma: no cover - implied by `supported`
            excluded.append((relative, ExclusionReason.UNSUPPORTED_LANGUAGE))
            continue

        units.append(
            TranslationUnit(
                file=relative,
                directory=entry.directory,
                arguments=list(entry.arguments),
                output=entry.output,
                language=language,
                std=std.raw if std is not None else None,
            )
        )
    return units, excluded


def _exclusion_limitations(
    excluded: list[tuple[PurePosixPath, ExclusionReason]],
) -> list[Limitation]:
    """One summary per reason. The full list lives in ``ScanPlan.excluded``.

    A limitation per excluded file would bury the report on any repository
    that vendors anything; a count plus the reason is what a reader acts on,
    and the per-file detail is one field away.
    """
    by_reason: dict[ExclusionReason, list[PurePosixPath]] = defaultdict(list)
    for path, reason in excluded:
        by_reason[reason].append(path)

    kinds = {
        ExclusionReason.THIRD_PARTY: LimitationKind.EXCLUDED_BY_FILTER,
        ExclusionReason.GENERATED: LimitationKind.GENERATED_CODE_UNAVAILABLE,
        ExclusionReason.TOO_LARGE: LimitationKind.FILE_TOO_LARGE,
        ExclusionReason.NOT_SELECTED: LimitationKind.EXCLUDED_BY_FILTER,
        ExclusionReason.MISSING_SOURCE: LimitationKind.MISSING_BUILD_TARGET,
        ExclusionReason.UNSUPPORTED_LANGUAGE: LimitationKind.EXCLUDED_BY_FILTER,
    }
    limitations: list[Limitation] = []
    for reason in ExclusionReason:
        paths = sorted(by_reason.get(reason, []), key=str)
        if not paths:
            continue
        limitations.append(
            Limitation(
                kind=kinds[reason],
                detail=(
                    f"{len(paths)} translation unit(s) excluded as {reason.value}; "
                    "no finding can be reported in them"
                ),
                affects=_summarize(paths),
            )
        )
    return limitations


def _outside_limitation(outside: list[Path]) -> Limitation:
    return Limitation(
        kind=LimitationKind.MISSING_BUILD_TARGET,
        detail=(
            f"{len(outside)} database entry/entries compile files outside the repository "
            "root and were not analysed; they have no repository-relative path, so nothing "
            "in them could be cited"
        ),
        affects=_summarize(outside),
    )


def _summarize(paths: Sequence[PurePosixPath] | Sequence[Path]) -> str:
    shown = ", ".join(str(path) for path in paths[:_MAX_NAMED])
    remainder = len(paths) - min(len(paths), _MAX_NAMED)
    return f"{shown} (and {remainder} more)" if remainder else shown


def _dedupe_limitations(limitations: Iterable[Limitation]) -> list[Limitation]:
    """Preserve order, drop exact repeats."""
    seen: list[Limitation] = []
    for limitation in limitations:
        if limitation not in seen:
            seen.append(limitation)
    return seen
