"""``run-manifest.json`` assembly.

The manifest is the only artifact allowed to carry a clock reading, a
duration, or an absolute path. Everything a report says about *what* was
found lives in the other two files and is diffable across runs and machines;
everything about *when and where* the run happened lives here.

Completeness is enforced rather than hoped for. A run whose analyzer version,
policy version, or revision is unknown cannot be reproduced, so
:func:`assemble_manifest` raises instead of writing a null — that is the
difference between a manifest and a log line.

The manifest type itself is :class:`caudit.model.manifest.RunManifest`, owned
by part 02 and schema-exported. Part 08's interface sketch names some fields
differently; the mapping is:

============================  ==========================================
``my_docs/plan`` sketch       ``RunManifest``
============================  ==========================================
``repo_root_name``            ``repository_root``
``dirty``                     ``revision_dirty``
``analyzer_versions``         ``tools`` (name + version + resolved path)
``model_ids``                 ``models`` — empty unless a model stage ran
``finding_hashes``            ``cited_region_hashes``
``counts``                    ``coverage.confirmed_count`` /
                              ``coverage.review_required_count``
============================  ==========================================
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import PurePath
from typing import Final

from caudit.config.loader import Config
from caudit.errors import CauditError
from caudit.evidence.hashing import hash_bytes
from caudit.intake.plan import ScanPlan
from caudit.model.manifest import (
    CoverageReport,
    ModelRecord,
    RunManifest,
    StageRecord,
    ToolRecord,
)
from caudit.report.sections import ReportSections
from caudit.status import ExitCode

__all__ = [
    "VOLATILE_FIELDS",
    "ReportError",
    "assemble_manifest",
    "config_fingerprint",
    "path_redactor",
    "repo_display_name",
    "reproducibility_diff",
]


class ReportError(CauditError):
    """A report cannot be written as described (part 08)."""

    exit_code = ExitCode.INTERNAL


#: Manifest fields that legitimately differ between two runs over identical
#: inputs. Everything else differing means the run was not reproducible, so
#: this allowlist is what turns "reproducible" into a checked property rather
#: than a claim. Keep it minimal: each entry is a comparison given up.
VOLATILE_FIELDS: Final[frozenset[str]] = frozenset({"started_at", "finished_at"})

#: What a tool version says when the tool ran but would not name itself.
#: Accepting it would put an unreproducible run behind a complete-looking
#: manifest, so it is treated as absent.
UNKNOWN_VERSION: Final = "unknown"


def repo_display_name(manifest: RunManifest) -> str:
    """The repository's own name — never the absolute path it sits at.

    Used by both other artifacts. A root with no name of its own (``/``) falls
    back to a description rather than to the path, because the path is exactly
    what must not appear outside this file.
    """
    return PurePath(manifest.repository_root).name or "the scanned tree"


def path_redactor(manifest: RunManifest) -> Callable[[str], str]:
    """A function that removes this run's absolute paths from rendered text.

    Free text reaches the report from parts that are allowed to know where the
    tree lives: an intake limitation naming the root, an analyzer message
    quoting the file it was handed. AC-08-11 is a property of the *artifact*,
    so it is enforced where the artifact is produced rather than by asking
    every upstream part to sanitize its own strings.

    Longest prefix first, so a compilation database inside the tree is not
    half-rewritten by the shorter root replacement. A root with no name of its
    own — ``/`` — is left alone: substituting it would rewrite every path in
    the document.
    """
    replacements: list[tuple[str, str]] = []
    database = manifest.compile_commands_path
    if database:
        replacements.append((database, PurePath(database).name))
    root = manifest.repository_root
    if PurePath(root).name:
        replacements.append((root, PurePath(root).name))
    replacements.sort(key=lambda pair: len(pair[0]), reverse=True)

    def redact(text: str) -> str:
        for absolute, relative in replacements:
            text = text.replace(absolute, relative)
        return text

    return redact


def config_fingerprint(config: Config) -> str:
    """Content address of the effective configuration.

    Over the serialized configuration with sorted keys, so two processes that
    built the same config from different layers — a file here, an environment
    variable there — agree on the hash.
    """
    payload = json.dumps(config.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
    return hash_bytes(payload.encode("utf-8"))


def assemble_manifest(
    *,
    plan: ScanPlan,
    sections: ReportSections,
    config: Config,
    caudit_version: str,
    started_at: datetime,
    finished_at: datetime,
    analyzer_versions: Mapping[str, str],
    analyzers_that_ran: Iterable[str],
    policy_versions: Mapping[str, str],
    units_parsed: int = 0,
    units_failed: int = 0,
    lines_of_code: int = 0,
    tool_paths: Mapping[str, str] | None = None,
    models: Sequence[ModelRecord] = (),
    stages: Sequence[StageRecord] = (),
    total_cost_usd: float = 0.0,
) -> RunManifest:
    """Build the manifest, or fail naming what is missing.

    ``analyzers_that_ran`` and ``analyzer_versions`` are separate arguments on
    purpose: an analyzer that ran and has no recorded version is the failure
    this function exists to catch, and it is only visible when the two lists
    are compared.

    ``models`` is empty when no model stage participated, and that emptiness is
    itself the claim: no tier was consulted. A stage that ran passes one record
    per configured tier, including tiers it never called — ``calls=0`` says a
    model was configured and not asked, where a missing row says nothing at all.

    ``stages`` and ``total_cost_usd`` are what part 12 completes the manifest
    with. Both belong here rather than in the other two artifacts for the same
    reason the timestamps do: a duration and a price are properties of one
    execution, and ``report.md`` and ``results.sarif`` have to stay
    byte-identical across two runs of one revision.
    """
    tools = _tool_records(analyzer_versions, analyzers_that_ran, tool_paths or {})
    policies = _checked_policies(policy_versions)
    if not plan.revision.strip():
        raise ReportError(
            "the scanned revision is blank, so this run cannot be reproduced or compared",
            hint="Intake records 'unknown' for a tree that is not a repository; a "
            "blank revision means the plan was built by hand.",
        )

    coverage = CoverageReport(
        translation_units_total=plan.coverage.tus_selected,
        translation_units_parsed=units_parsed,
        translation_units_failed=units_failed,
        excluded_paths=[path for path, _ in plan.excluded],
        excluded_reasons={str(path): str(reason) for path, reason in plan.excluded},
        lines_of_code=lines_of_code,
        confirmed_count=sections.confirmed_count,
        review_required_count=sections.review_count,
    )
    return RunManifest(
        caudit_version=caudit_version,
        started_at=started_at,
        finished_at=finished_at,
        repository_root=str(plan.repo_root),
        revision=plan.revision,
        revision_dirty=plan.dirty,
        compile_commands_path=str(plan.compile_commands_path),
        compile_commands_sha256=_database_hash(plan),
        tools=tools,
        models=list(models),
        config_snapshot=config.model_dump(mode="json"),
        config_hash=config_fingerprint(config),
        policy_versions=policies,
        cited_region_hashes=sections.region_hashes(),
        coverage=coverage,
        stages=list(stages),
        total_cost_usd=total_cost_usd,
    )


def reproducibility_diff(
    left: RunManifest,
    right: RunManifest,
    *,
    allow: Iterable[str] = VOLATILE_FIELDS,
) -> dict[str, tuple[object, object]]:
    """Fields that differ between two manifests, minus the volatile allowlist.

    An empty result means the two runs are reproductions of each other. A
    non-empty one names exactly which field broke the claim.

    Stage *durations* are dropped before comparing and stage *statuses* are
    not. A second run being faster says nothing about reproducibility; a second
    run in which the index degraded says everything, and putting ``stages`` on
    the volatile allowlist wholesale would hide the second to excuse the first.
    """
    allowed = set(allow)
    first = _comparable(left)
    second = _comparable(right)
    return {
        key: (first.get(key), second.get(key))
        for key in sorted(set(first) | set(second))
        if key not in allowed and first.get(key) != second.get(key)
    }


def _comparable(manifest: RunManifest) -> dict[str, object]:
    """A manifest as JSON, with the values no two runs can share removed."""
    payload = manifest.model_dump(mode="json")
    stages = payload.get("stages")
    if isinstance(stages, list):
        payload["stages"] = [
            {key: value for key, value in record.items() if key != "duration_seconds"}
            if isinstance(record, dict)
            else record
            for record in stages
        ]
    return payload


# ---------------------------------------------------------------- internals


def _tool_records(
    versions: Mapping[str, str],
    ran: Iterable[str],
    paths: Mapping[str, str],
) -> list[ToolRecord]:
    """One record per tool that ran, sorted by name. Missing versions raise."""
    names = sorted(set(ran))
    if not names:
        raise ReportError(
            "no tool ran, so there is nothing to record a version for and the run "
            "cannot be reproduced",
            hint="Run 'caudit doctor' to see which components are missing, then scan again.",
        )
    missing = [
        name
        for name in names
        if not versions.get(name, "").strip() or versions[name].strip() == UNKNOWN_VERSION
    ]
    if missing:
        raise ReportError(
            f"no version was recorded for {', '.join(missing)}, so this run cannot be "
            "reproduced; the manifest is complete or the run fails",
            hint=(
                "The tool ran but did not report a version. Check that "
                f"`{missing[0]} --version` prints one."
            ),
        )
    return [
        ToolRecord(name=name, version=versions[name].strip(), path=paths.get(name))
        for name in names
    ]


def _database_hash(plan: ScanPlan) -> str | None:
    """The compilation database's own hash, derived rather than passed in.

    A caller cannot forget it, and it cannot disagree with the path recorded
    beside it. ``None`` only when the file has gone since intake read it.
    """
    try:
        return hash_bytes(plan.compile_commands_path.read_bytes())
    except OSError:
        return None


def _checked_policies(policy_versions: Mapping[str, str]) -> dict[str, str]:
    """Policy versions, sorted, with a blank one treated as an error."""
    blank = sorted(key for key, value in policy_versions.items() if not str(value).strip())
    if blank:
        raise ReportError(
            f"policy version(s) {', '.join(blank)} are blank; a report that cannot name "
            "the policies that produced it cannot be compared to another run"
        )
    return {key: str(policy_versions[key]).strip() for key in sorted(policy_versions)}
