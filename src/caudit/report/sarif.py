"""SARIF 2.1.0 output.

Validated in tests against the official schema vendored at
``schemas/sarif-2.1.0.schema.json``, so "SARIF-compatible" is a checked
property of this module rather than a claim in a README.

The load-bearing decision is `AC-08-2`: a review-required item serializes as
``kind="review"`` with ``level="none"``, and a confirmed finding as
``kind="fail"``. A code-scanning system that ingests this file therefore
cannot silently count the two together — the spec's separation survives the
export, not just the Markdown.

Three deliberate omissions, each because including it would break
byte-reproducibility or say something untrue:

* ``results[].provenance``. Every field the SARIF ``resultProvenance`` object
  defines is a timestamp or a conversion source. Analyzer provenance goes in
  ``properties.producers`` instead, which is what the plan's mapping table
  asks the field to carry.
* ``invocations[].startTimeUtc`` and friends. Clock readings live only in
  ``run-manifest.json``.
* ``originalUriBaseIds[%SRCROOT%].uri``. Defining it would put the absolute
  repository path in the artifact. The base id is declared with a
  *description* naming the root instead, and the absolute path is in the
  manifest for anyone who needs to resolve it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from caudit.finding_policy.provenance import claim_provenance
from caudit.finding_policy.ranking import explain, rank_inputs
from caudit.model.cwe import ALLOWLIST, family_of
from caudit.model.evidence import EvidenceItem, EvidenceKind
from caudit.model.finding import Finding, Limitation, Severity
from caudit.model.manifest import RunManifest
from caudit.model.source import SourceRegion
from caudit.report.manifest import path_redactor, repo_display_name
from caudit.report.sections import ReportSections

__all__ = ["CWE_TAXONOMY_GUID", "SARIF_SCHEMA_URI", "SARIF_VERSION", "build_sarif", "render_sarif"]

SARIF_VERSION: Final = "2.1.0"
SARIF_SCHEMA_URI: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

#: A fixed guid, not a generated one. A run identifier that changed every
#: execution would defeat the byte-identical requirement in AC-08-7.
CWE_TAXONOMY_GUID: Final = "b3e0f1a4-8c2d-4b7e-9f31-3f0a6d5c7e21"

#: Repository-relative locations are expressed against this base id. It is
#: declared without a uri — see the module docstring.
SRCROOT: Final = "%SRCROOT%"

#: Confirmed severity → SARIF level. Needs-review never reaches this table:
#: it is ``none`` regardless of severity, so that a consumer sorting by level
#: cannot promote an unverified item.
_LEVEL_FOR_SEVERITY: Final[Mapping[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

#: Notification descriptor ids, so a consumer can filter one class of note.
_COVERAGE_NOTE: Final = "caudit/coverage"
_EXCLUDED_NOTE: Final = "caudit/excluded"
_LIMITATION_NOTE: Final = "caudit/limitation"
_REVIEW_NOTE: Final = "caudit/needs-review"
_RUN_NOTE: Final = "caudit/note"
_PARTIAL_NOTE: Final = "caudit/partial"


def render_sarif(sections: ReportSections, manifest: RunManifest) -> str:
    """Deterministic JSON text: sorted keys, two-space indent, trailing newline."""
    document = build_sarif(sections, manifest)
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_sarif(sections: ReportSections, manifest: RunManifest) -> dict[str, Any]:
    """The whole SARIF log as plain data, ready to serialize or assert on."""
    findings = [*sections.confirmed, *sections.needs_review]
    rules = _rules(findings)
    rule_index = {rule["id"]: position for position, rule in enumerate(rules)}
    taxa = _taxa(findings)
    taxon_index = {entry["id"]: position for position, entry in enumerate(taxa)}

    # ``rank`` is the 1-based position within a section, so a consumer that
    # re-sorts by its own rules can still recover the order this report argued
    # for. The two sections are numbered independently: a review item is not
    # ranked against a confirmed finding, and giving them one sequence would
    # imply an ordering between them that does not exist.
    results = [
        _result(
            finding,
            rule_index,
            taxon_index,
            kind="fail",
            level=_level(finding),
            rank=position,
        )
        for position, finding in enumerate(sections.confirmed, start=1)
    ]
    results.extend(
        _result(
            finding,
            rule_index,
            taxon_index,
            kind="review",
            level="none",
            note=sections.unresolved.get(finding.finding_id),
            rank=position,
        )
        for position, finding in enumerate(sections.needs_review, start=1)
    )

    run: dict[str, Any] = {
        "tool": _tool(manifest, rules),
        "originalUriBaseIds": {
            SRCROOT: {
                "description": {
                    "text": (
                        f"Repository root '{repo_display_name(manifest)}' at revision "
                        f"{manifest.revision}. The absolute path is recorded in "
                        "run-manifest.json, deliberately not here."
                    )
                }
            }
        },
        "columnKind": "utf16CodeUnits",
        "invocations": [
            {
                # False on a partial run. A code-scanning system that ingests
                # this file decides whether to trust the result set from here,
                # and a run whose index or analyzer stage failed produced a
                # result set that is missing entries rather than short of them.
                "executionSuccessful": not manifest.partial,
                "toolExecutionNotifications": _notifications(sections, manifest),
            }
        ],
        "results": results,
    }
    if taxa:
        run["taxonomies"] = [_cwe_taxonomy(taxa)]
    document = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    # Over the assembled document rather than at each call site, so free text
    # arriving from another part — an intake limitation naming the root, an
    # analyzer message quoting the file it was handed — cannot slip an
    # absolute path past AC-08-11. Applied to the data, not to the serialized
    # text, so JSON escaping is never a factor.
    redacted: dict[str, Any] = _redact(document, path_redactor(manifest))
    return redacted


# -------------------------------------------------------------------- tool


def _tool(manifest: RunManifest, rules: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The driver, plus one extension per analyzer that actually ran."""
    return {
        "driver": {
            "name": "caudit",
            "version": manifest.caudit_version,
            "informationUri": "https://github.com/caudit/caudit",
            "semanticVersion": manifest.caudit_version,
            "rules": list(rules),
        },
        "extensions": [{"name": tool.name, "version": tool.version} for tool in manifest.tools],
    }


def _rules(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    """One rule per analyzer check, with the union of the CWEs it produced.

    Keyed by the analyzer's own rule id, because that is what a consumer
    suppresses, tunes, or files a bug against. The CWE is expressed on the
    rule as a tag *and* as a taxonomy relationship, never as the identity.
    """
    cwes: dict[str, set[str]] = {}
    names: dict[str, str] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        cwes.setdefault(rule_id, set()).add(finding.cwe)
        names.setdefault(rule_id, finding.provenance[0].tool_name)

    rules: list[dict[str, Any]] = []
    for rule_id in sorted(cwes):
        tags = ["security", *sorted(cwes[rule_id], key=_cwe_sort_key)]
        families = sorted(
            {str(family) for cwe in cwes[rule_id] if (family := family_of(cwe)) is not None}
        )
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": f"{names[rule_id]} check {rule_id}"},
            "help": {
                "text": (
                    f"Reported by {names[rule_id]}. C Audit maps this check to "
                    f"{', '.join(sorted(cwes[rule_id], key=_cwe_sort_key))} through its "
                    "committed rule-to-CWE table; the mapping is data, not inference."
                )
            },
            "properties": {"tags": [*tags, *families]},
            "relationships": [
                {
                    "target": {
                        "id": cwe,
                        "toolComponent": {"name": "CWE", "guid": CWE_TAXONOMY_GUID},
                    },
                    "kinds": ["superset"],
                }
                for cwe in sorted(cwes[rule_id], key=_cwe_sort_key)
            ],
        }
        rules.append(rule)
    return rules


def _rule_id(finding: Finding) -> str:
    """The analyzer's check id, or a stable stand-in naming the producer."""
    rule = finding.provenance[0].rule_id
    if rule:
        return rule
    return f"caudit/unmapped-{finding.provenance[0].producer}"


def _taxa(findings: Sequence[Finding]) -> list[dict[str, Any]]:
    """Every CWE this run used, as taxonomy entries, sorted numerically."""
    used = sorted({finding.cwe for finding in findings}, key=_cwe_sort_key)
    entries: list[dict[str, Any]] = []
    for cwe in used:
        allowlisted = ALLOWLIST.get(cwe)
        entries.append(
            {
                "id": cwe,
                "name": allowlisted.name if allowlisted else cwe,
                "shortDescription": {
                    "text": allowlisted.name if allowlisted else f"{cwe} (outside the allowlist)"
                },
            }
        )
    return entries


def _cwe_taxonomy(taxa: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": "CWE",
        "guid": CWE_TAXONOMY_GUID,
        "organization": "MITRE",
        "shortDescription": {"text": "Common Weakness Enumeration"},
        "informationUri": "https://cwe.mitre.org/data/index.html",
        "isComprehensive": False,
        "taxa": list(taxa),
    }


# ------------------------------------------------------------------ results


def _result(
    finding: Finding,
    rule_index: Mapping[str, int],
    taxon_index: Mapping[str, int],
    *,
    kind: str,
    level: str,
    note: str | None = None,
    rank: int = 0,
) -> dict[str, Any]:
    rule_id = _rule_id(finding)
    inputs = rank_inputs(finding)
    provenance = claim_provenance(finding)
    text = finding.impact.description
    if note:
        text = f"{text} [needs review — {note}]"
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index[rule_id],
        "kind": kind,
        "level": level,
        "message": {"text": text},
        "locations": [_location(finding.location, symbol=_symbol_name(finding))],
        "partialFingerprints": {"caudit/v1": finding.fingerprint},
        "properties": {
            "confidence": str(finding.confidence),
            "confidenceReason": str(finding.confidence_reason),
            "findingId": finding.finding_id,
            "cwe": finding.cwe,
            "impactKind": str(finding.impact.kind),
            "severity": str(finding.impact.severity),
            "reachability": str(finding.reachability),
            "exploitability": str(finding.exploitability),
            "producers": sorted(entry.describe() for entry in finding.provenance),
            "regionHash": finding.location.sha256,
            "remediation": finding.remediation.strategy,
            "evidenceSupports": finding.impact.evidence_supports,
            "rank": rank,
            "rankSeverity": str(inputs.severity),
            "rankEffort": str(inputs.effort),
            "provenanceAgreement": inputs.provenance_agreement,
            "rankExplanation": explain(finding, inputs),
            # Per-claim, not per-finding: which producer stands behind which
            # part of the argument. ``aiProvenance`` is empty on a run where no
            # model was consulted, and that emptiness is the claim.
            "aiProvenance": list(provenance.models),
            "claimProvenance": provenance.describe(),
            "factProducers": [f"{fact} — {who}" for fact, who in provenance.facts],
        },
    }
    if finding.cwe in taxon_index:
        result["taxa"] = [
            {
                "id": finding.cwe,
                "index": taxon_index[finding.cwe],
                "toolComponent": {"name": "CWE", "guid": CWE_TAXONOMY_GUID},
            }
        ]
    flow = _code_flow(finding)
    if flow is not None:
        result["codeFlows"] = [flow]
    if finding.limitations:
        result["properties"]["limitations"] = [
            f"[{limitation.kind}] {limitation.detail}" for limitation in finding.limitations
        ]
    return result


def _symbol_name(finding: Finding) -> str | None:
    return finding.symbol.name if finding.symbol else None


def _level(finding: Finding) -> str:
    return _LEVEL_FOR_SEVERITY[finding.impact.severity]


def _location(region: SourceRegion, *, symbol: str | None = None) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": str(region.path), "uriBaseId": SRCROOT},
            "region": {
                "startLine": region.start_line,
                "endLine": region.end_line,
                "byteOffset": region.start_byte,
                "byteLength": region.byte_length,
                "properties": {"sha256": region.sha256},
            },
        }
    }
    if symbol:
        location["logicalLocations"] = [{"name": symbol, "kind": "function"}]
    return location


def _code_flow(finding: Finding) -> dict[str, Any] | None:
    """The analyzer's path, in the order it walked it.

    Only ``control_flow_step`` evidence becomes a flow. A supporting type
    declaration is evidence, but presenting it as step three of an execution
    path would assert an ordering the analyzer never claimed.
    """
    steps = [item for item in finding.evidence if item.kind is EvidenceKind.CONTROL_FLOW_STEP]
    if not steps:
        return None
    return {
        "threadFlows": [
            {
                "locations": [
                    _thread_flow_location(step, order) for order, step in enumerate(steps, start=1)
                ]
            }
        ]
    }


def _thread_flow_location(step: EvidenceItem, order: int) -> dict[str, Any]:
    return {
        "location": _location(step.region, symbol=step.symbol.name if step.symbol else None),
        "nestingLevel": 0,
        "executionOrder": order,
    }


# ------------------------------------------------------------ notifications


def _notifications(sections: ReportSections, manifest: RunManifest) -> list[dict[str, Any]]:
    """Coverage, exclusions, limitations and run notes, in a fixed order.

    These are ``toolExecutionNotifications`` rather than results because they
    are statements about the run, not about the code. A reader who only ever
    looks at ``results`` still sees a complete list of findings; a reader who
    wants to know what was never examined finds it here.

    The partial notice comes first, at ``error``, because it is the one
    statement that changes how everything after it should be read. Durations
    are deliberately not in it: a stage's *status* is a fact about the run that
    two reproductions share, and its duration is not.
    """
    coverage = sections.coverage
    notifications: list[dict[str, Any]] = []
    if manifest.partial:
        notifications.append(
            _notification(
                _PARTIAL_NOTE,
                "error",
                "This report is partial. "
                + "; ".join(
                    f"the {record.stage} stage {record.status}: {record.detail}"
                    for record in manifest.failed_stages()
                    if record.detail
                )
                + ". Results are missing rather than absent — do not read this run as a "
                "clean result.",
            )
        )
    notifications.extend(
        [
            _notification(
                _COVERAGE_NOTE,
                "note" if coverage.is_complete else "warning",
                f"Coverage: {coverage.describe()}.",
            ),
            _notification(
                _REVIEW_NOTE,
                "note",
                (
                    f"{sections.confirmed_count} confirmed finding(s) and "
                    f"{sections.review_count} item(s) needing review. The two counts are "
                    "reported separately and are never added: a review-required item is "
                    "a candidate whose evidence did not fully resolve, not a vulnerability."
                ),
            ),
        ]
    )
    for path, reason in sections.excluded:
        notifications.append(
            _notification(_EXCLUDED_NOTE, "note", f"Excluded from the scan: {path} ({reason}).")
        )
    for limitation in sections.limitations:
        notifications.append(
            _notification(_LIMITATION_NOTE, "warning", _limitation_text(limitation))
        )
    for note in sections.notes:
        notifications.append(_notification(_RUN_NOTE, "warning", note))
    return notifications


def _limitation_text(limitation: Limitation) -> str:
    where = f" ({limitation.affects})" if limitation.affects else ""
    return f"[{limitation.kind}]{where} {limitation.detail}"


def _notification(descriptor: str, level: str, text: str) -> dict[str, Any]:
    return {
        "descriptor": {"id": descriptor},
        "level": level,
        "message": {"text": text},
    }


def _redact(node: Any, redact: Callable[[str], str]) -> Any:
    """Apply ``redact`` to every string in a JSON-shaped structure."""
    if isinstance(node, str):
        return redact(node)
    if isinstance(node, dict):
        return {key: _redact(value, redact) for key, value in node.items()}
    if isinstance(node, list):
        return [_redact(value, redact) for value in node]
    return node


def _cwe_sort_key(cwe: str) -> tuple[int, str]:
    digits = cwe.rpartition("-")[2]
    return (int(digits) if digits.isdigit() else 0, cwe)
