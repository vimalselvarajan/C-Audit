"""Part 12 end to end: T-12-09 to T-12-12, T-12-16, T-12-17.

The whole pipeline through ``run_scan``, offline. Analyzers are stubbed at the
subprocess boundary (part 08's arrangement, reused) and the model stage is
driven by :class:`~tests.conftest.ScriptedProvider`, so intake, indexing,
candidate generation, expansion, adjudication, the gate, ranking and all three
artifacts run exactly as they do in production with no socket and no key.

T-12-09's row names ``needs_clang``. It is not marked so here: stubbing the
subprocess layer exercises the same command lines, parsers and normalizer, and
the real-toolchain confirmation of those recordings is T-08-17's job. What that
leaves untested here is Clang itself, which no part 12 acceptance criterion is
about.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from rich.console import Console

from caudit.application.scan import ScanResult, run_scan
from caudit.config.loader import Config
from caudit.llm.service import LLMProvider
from caudit.model.finding import Confidence
from caudit.model.manifest import RunManifest, StageStatus
from caudit.status import ExitCode
from tests.conftest import ScriptedProvider, demo_project

CONSENTED = Config.model_validate({"cloud_consent": True, "llm": {"triage_enabled": False}})


def _console() -> Console:
    return Console(soft_wrap=True, highlight=False, markup=False, quiet=True)


def _run(
    root: Path,
    database: Path,
    out: Path,
    *,
    config: Config | None = None,
    provider: LLMProvider | None = None,
    remember: bool = False,
) -> ScanResult:
    return run_scan(
        root,
        database,
        config or Config(),
        out=out,
        console=_console(),
        provider=provider,
        remember=remember,
    )


def _artifacts(out: Path) -> tuple[str, dict[str, object], RunManifest]:
    report = (out / "report.md").read_text(encoding="utf-8")
    sarif: dict[str, object] = json.loads((out / "results.sarif").read_text(encoding="utf-8"))
    manifest = RunManifest.model_validate_json((out / "run-manifest.json").read_text("utf-8"))
    return report, sarif, manifest


# ------------------------------------------------------------------- T-12-09


@pytest.mark.needs_libclang
def test_a_consented_scan_records_models_tokens_and_policy_versions(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """T-12-09 (AC-12-5): the manifest is complete for a run with a model in it."""
    root, database = demo_project(tmp_path)
    out = tmp_path / "out"
    provider = ScriptedProvider()

    result = _run(root, database, out, config=CONSENTED, provider=provider)

    report, sarif, manifest = _artifacts(out)
    assert provider.calls > 0, "the consented path never reached the provider"

    # Model ids, per tier, from configuration rather than from the architecture.
    assert [record.tier for record in manifest.models] == ["triage", "adjudication", "escalation"]
    adjudication = next(r for r in manifest.models if r.tier == "adjudication")
    assert adjudication.model_id == CONSENTED.models.adjudication
    assert adjudication.calls > 0
    assert adjudication.input_tokens > 0

    assert set(manifest.policy_versions) >= {"matching", "profile", "prompt", "retrieval"}
    assert manifest.policy_versions["prompt"] == CONSENTED.policy_versions.prompt

    # The model's contribution is named per finding, not as one badge.
    assert "**Provenance.**" in report
    assert CONSENTED.models.adjudication in report
    ai = [r["properties"]["aiProvenance"] for r in sarif["runs"][0]["results"]]  # type: ignore[index]
    assert any(entry for entry in ai), "no result recorded which model spoke for it"
    assert result.exit_code in {ExitCode.OK, ExitCode.FINDINGS}


@pytest.mark.needs_libclang
def test_a_consented_scan_records_per_stage_timings_and_spend(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """T-12-15 (AC-12-10): every stage timed, and the run's total spend."""
    root, database = demo_project(tmp_path)
    out = tmp_path / "out"
    _run(root, database, out, config=CONSENTED, provider=ScriptedProvider())

    _report, _sarif, manifest = _artifacts(out)
    stages = {record.stage for record in manifest.stages}
    assert stages == {"intake", "index", "candidates", "adjudication"}
    # Rendering is deliberately absent: a stage cannot record its own duration
    # in the file it is writing, and the manifest carries the stages that
    # decided its content.
    assert "report" not in stages
    assert all(record.duration_seconds >= 0.0 for record in manifest.stages)
    # Zero spend, because every configured tier is priced at zero by default —
    # which is a recorded fact, not a missing one.
    assert manifest.total_cost_usd == 0.0
    assert not manifest.partial


# ------------------------------------------------------------------- T-12-10


@pytest.mark.needs_libclang
def test_a_scan_without_consent_opens_no_socket_and_names_no_model(
    tmp_path: Path, stubbed_analyzers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-12-10 (AC-12-6): the same three artifacts, and nothing transmitted.

    The socket constructor is replaced with one that fails the test, which is
    stronger than counting requests afterwards: an attempt fails where it
    happens, with a stack naming the caller.
    """

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a socket was opened during a scan without consent")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    root, database = demo_project(tmp_path)
    out = tmp_path / "out"
    _run(root, database, out)

    report, _sarif, manifest = _artifacts(out)
    assert manifest.models == []
    assert manifest.total_cost_usd == 0.0
    assert "none consulted" in report
    assert "no model looked" in report or "deterministic analyzer baseline" in report

    skipped = {r.stage for r in manifest.stages if r.status is StageStatus.SKIPPED}
    assert skipped == {"expansion", "adjudication", "verification"}
    # Skipping is not degrading: nobody asked for a model, so nothing failed.
    assert not manifest.partial


@pytest.mark.needs_libclang
def test_the_unconsented_report_is_the_milestone_1_baseline(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """AC-12-6: a run without consent is byte-identical to the part 08 report.

    Not merely similar. The M2 comparison measures an adjudicated run against
    this one, so if consent changed the *baseline* the delta would be measuring
    two different reports rather than the model's contribution.
    """
    root, database = demo_project(tmp_path)
    from caudit.cli.main import main

    part_08 = tmp_path / "part08"
    part_12 = tmp_path / "part12"
    main(["scan", str(root), "--compile-commands", str(database), "--out", str(part_08)])
    _run(root, database, part_12)

    assert (part_12 / "report.md").read_bytes() == (part_08 / "report.md").read_bytes()
    assert (part_12 / "results.sarif").read_bytes() == (part_08 / "results.sarif").read_bytes()


# ------------------------------------------------------------------- T-12-11


@pytest.mark.needs_libclang
def test_two_consented_runs_with_a_warm_cache_are_byte_identical(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """T-12-11 (AC-12-7): determinism survives the model.

    Both runs share one cache directory, so the second replays the first's
    answers. What must not differ is the Markdown and the SARIF; the manifest
    legitimately does, because the second run made no calls.
    """
    root, database = demo_project(tmp_path)
    cache = tmp_path / "llm-cache"
    config = Config.model_validate(
        {
            "cloud_consent": True,
            "llm": {"triage_enabled": False, "cache_enabled": True, "cache_dir": str(cache)},
        }
    )

    first = tmp_path / "first"
    second = tmp_path / "second"
    _run(root, database, first, config=config, provider=ScriptedProvider())
    _run(root, database, second, config=config, provider=ScriptedProvider())

    for name in ("report.md", "results.sarif"):
        assert (first / name).read_bytes() == (second / name).read_bytes(), name

    warm = _artifacts(second)[2]
    assert sum(record.calls for record in warm.models) == 0, "the cache was not warm"


# ------------------------------------------------------------------- T-12-12


@pytest.mark.needs_libclang
def test_exit_codes_say_what_happened(tmp_path: Path, stubbed_analyzers: None) -> None:
    """T-12-12 (AC-12-8): 1 with findings, 3 when nothing could look."""
    root, database = demo_project(tmp_path)
    found = _run(root, database, tmp_path / "found")
    assert found.exit_code is ExitCode.FINDINGS
    assert found.artifacts.sections.confirmed_count > 0


@pytest.mark.needs_libclang
def test_a_run_with_no_analyzer_exits_three_rather_than_zero(
    tmp_path: Path, no_analyzers: None
) -> None:
    """T-12-12 (AC-12-8): ``0`` must never mean "we did not look".

    The absence is imposed by the fixture. It used to come from the machine,
    which meant this test asserted its own premise anywhere Clang was
    installed.
    """
    root, database = demo_project(tmp_path)
    result = _run(root, database, tmp_path / "out")
    assert result.exit_code is ExitCode.ENVIRONMENT
    assert "No analyzer ran" in (tmp_path / "out" / "report.md").read_text(encoding="utf-8")


def test_a_missing_compilation_database_is_a_usage_error(tmp_path: Path) -> None:
    """T-12-12 (AC-12-8): exit 2, with instructions rather than a guess."""
    from caudit.cli.main import main

    root, _database = demo_project(tmp_path)
    code = main(["scan", str(root), "--out", str(tmp_path / "out")])
    assert code == int(ExitCode.USAGE)


# ------------------------------------------------------------------- T-12-16


@pytest.mark.needs_libclang
def test_a_provider_that_dies_mid_run_still_produces_a_report(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """T-12-16 (AC-12-11): partial, not absent, and not a traceback.

    The first candidate is answered and the rest are not. Both outcomes are in
    the report: one adjudicated finding, and the remaining candidates carried
    forward on the analyzer's word with ``provider_unavailable`` recorded.
    """
    root, database = demo_project(tmp_path)
    out = tmp_path / "out"
    provider = ScriptedProvider(fail_after=1)

    result = _run(root, database, out, config=CONSENTED, provider=provider)

    report, sarif, manifest = _artifacts(out)
    assert (out / "report.md").is_file() and (out / "results.sarif").is_file()
    assert result.exit_code is not ExitCode.OK

    assert manifest.partial
    assert report.startswith("# C Audit report (PARTIAL)")
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False  # type: ignore[index]

    reasons = {
        r["properties"]["confidenceReason"]
        for r in sarif["runs"][0]["results"]  # type: ignore[index]
    }
    assert "provider_unavailable" in reasons

    adjudication = next(r for r in manifest.stages if r.stage == "adjudication")
    assert adjudication.status is StageStatus.DEGRADED
    assert adjudication.detail and "not answered" in adjudication.detail


@pytest.mark.needs_libclang
def test_no_candidate_is_lost_when_the_model_stage_fails(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """AC-12-11: the count is the same with and without a working provider."""
    root, database = demo_project(tmp_path)
    healthy = _run(root, database, tmp_path / "ok", config=CONSENTED, provider=ScriptedProvider())
    broken = _run(
        root,
        database,
        tmp_path / "broken",
        config=CONSENTED,
        provider=ScriptedProvider(fail_after=0),
    )

    def total(result: ScanResult) -> int:
        sections = result.artifacts.sections
        return len(sections.confirmed) + len(sections.needs_review)

    assert total(healthy) == total(broken) > 0


# ------------------------------------------------------------------- T-12-17


@pytest.mark.needs_libclang
def test_a_translation_unit_that_will_not_parse_leaves_the_report_standing(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """T-12-17 (AC-12-11): coverage reflects the gap and a limitation names it.

    The run is *not* marked partial for this. A unit that will not parse is
    already counted in coverage, named in a limitation, and printed in the
    report's coverage section — it is the index doing its job. Partial is
    reserved for a stage that did not do its job, and a marker that fired on
    every repository with an unparseable header would stop being read.
    """
    root, database = demo_project(tmp_path)
    (root / "src" / "beta.c").write_text(
        '#include "no-such-header-anywhere.h"\nvoid broken(void) { return\n', encoding="utf-8"
    )
    out = tmp_path / "out"

    _run(root, database, out)
    report, _sarif, manifest = _artifacts(out)

    assert (out / "report.md").is_file()
    assert manifest.coverage.translation_units_failed >= 1
    assert "## Coverage" in report
    assert any("parse_failed" in limitation for limitation in report.splitlines())

    index_stage = next(r for r in manifest.stages if r.stage == "index")
    assert index_stage.status is StageStatus.OK
    assert index_stage.detail and "beta.c" in index_stage.detail
    assert not manifest.partial
    assert "PARTIAL" not in report


# --------------------------------------------------------------- ranking e2e


@pytest.mark.needs_libclang
def test_the_written_report_ranks_and_explains_every_finding(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """AC-12-4 as the user sees it: one explanation per rendered finding."""
    root, database = demo_project(tmp_path)
    out = tmp_path / "out"
    result = _run(root, database, out)

    report, sarif, _manifest = _artifacts(out)
    sections = result.artifacts.sections
    rendered = len(sections.confirmed) + len(sections.needs_review)
    assert report.count("**Why this rank**") == rendered

    ranks = [r["properties"]["rank"] for r in sarif["runs"][0]["results"]]  # type: ignore[index]
    assert all(isinstance(rank, int) and rank >= 1 for rank in ranks)
    assert all(
        r["properties"]["rankExplanation"]
        for r in sarif["runs"][0]["results"]  # type: ignore[index]
    )


@pytest.mark.needs_libclang
def test_a_repository_with_no_candidates_skips_the_model_stages(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """Nothing to adjudicate is not a failure, and no request is assembled."""
    root, database = demo_project(tmp_path)
    for name in ("alpha", "beta", "gamma"):
        (root / "src" / f"{name}.c").write_text("void nothing(void) {}\n", encoding="utf-8")

    provider = ScriptedProvider()
    result = _run(root, database, tmp_path / "out", config=CONSENTED, provider=provider)

    assert provider.calls == 0
    assert not result.partial
    _report, _sarif, manifest = _artifacts(tmp_path / "out")
    assert {r.status for r in manifest.stages if r.stage == "adjudication"} == {StageStatus.SKIPPED}


@pytest.mark.needs_libclang
def test_remember_consent_records_it_for_the_repository(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """``--remember-consent`` writes the record part 10 reads back."""
    root, database = demo_project(tmp_path)
    _run(root, database, tmp_path / "out", remember=True)

    from caudit.llm.service import consent_state

    decision = consent_state(Config(), root)
    assert decision.granted
    assert (root / ".caudit" / "cloud-consent.json").is_file()


def test_the_provider_cannot_be_built_without_consent() -> None:
    """AC-12-6 as a property of the type, not of this module's branching.

    ``run_scan`` only reaches :func:`adjudication_provider` on the consented
    branch. This asserts the second guard: even called directly, the backend
    refuses a decision that was not granted.
    """
    from caudit.application.providers import gemini_provider_factory
    from caudit.llm.service import ConsentDecision, ConsentError, ConsentSource

    refused = ConsentDecision(granted=False, source=ConsentSource.ABSENT, detail="not given")
    with pytest.raises(ConsentError):
        gemini_provider_factory(refused)

    granted = ConsentDecision(granted=True, source=ConsentSource.CONFIG, detail="granted")
    assert gemini_provider_factory(granted) is not None


@pytest.mark.needs_libclang
def test_the_confirmed_section_holds_only_confirmed_findings(
    tmp_path: Path, stubbed_analyzers: None
) -> None:
    """AC-12-2 through the CLI: the split survives the whole pipeline."""
    root, database = demo_project(tmp_path)
    result = _run(root, database, tmp_path / "out", config=CONSENTED, provider=ScriptedProvider())

    sections = result.artifacts.sections
    assert sections.confirmed, "nothing was confirmed, so this asserts nothing"
    assert all(f.confidence is not Confidence.REVIEW_REQUIRED for f in sections.confirmed)
    assert all(f.confidence is Confidence.REVIEW_REQUIRED for f in sections.needs_review)
