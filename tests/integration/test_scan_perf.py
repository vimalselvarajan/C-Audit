"""T-12-18: the 50-unit end-to-end budget. Marked `slow`, deselected by default.

Budgets, not targets. They exist to catch a change that makes the assembled
pipeline superlinear in the unit count, or that stops the run-level token
ledger from binding — both invisible on a three-file fixture and expensive on a
real repository.

The token ceiling is the one that matters most. A run that quietly spends
beyond ``token_budget.per_run`` produces a surprising invoice rather than a bad
report, which is the failure a user cannot see in any artifact.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from rich.console import Console

from caudit.application.scan import run_scan
from caudit.config.loader import Config
from tests.conftest import ScriptedProvider, stub_subprocess, write_compdb

pytestmark = [pytest.mark.slow, pytest.mark.needs_libclang]

#: Translation units in the generated tree.
UNITS = 50
#: Wall-clock ceiling for a cold consented run over that tree.
BUDGET_SECONDS = 300.0
#: The run's token ceiling, set well below what 50 units would cost unbounded
#: so the ledger has to bind for the test to pass at all.
BUDGET_TOKENS = 40_000


def generate_tree(root: Path, units: int) -> tuple[Path, Path]:
    """A synthetic repository with one defect per unit, plus its database."""
    source = root / "src"
    source.mkdir(parents=True)
    (source / "common.h").write_text(
        "#define CAPACITY 16\nstruct Item { char name[CAPACITY]; int size; };\n",
        encoding="utf-8",
    )
    for index in range(units):
        (source / f"unit{index}.c").write_text(
            '#include "common.h"\n'
            "#include <string.h>\n"
            "\n"
            f"void store{index}(struct Item *item, const char *value)\n"
            "{\n"
            "    /* No bound: value may be longer than name. */\n"
            "    strcpy(item->name, value);\n"
            "}\n"
            "\n"
            f"int size{index}(const struct Item *item)\n"
            "{\n"
            "    return item->size;\n"
            "}\n",
            encoding="utf-8",
        )
    database = write_compdb(
        root,
        [
            {
                "directory": str(root),
                "file": str(source / f"unit{index}.c"),
                "arguments": ["clang", "-std=c11", "-Isrc", "-c", str(source / f"unit{index}.c")],
            }
            for index in range(units)
        ],
    )
    return root, database


@pytest.fixture
def stubbed_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    """One diagnostic per unit, without launching a compiler 50 times."""
    from caudit.analyzers.normalize import Normalizer
    from caudit.analyzers.profile import load_profile
    from caudit.analyzers.runner import Analyzer
    from caudit.analyzers.service import build_analyzers
    from caudit.model.finding import Limitation

    output = "".join(
        f"src/unit{index}.c:7:5: warning: 'strcpy' is insecure [-Wdeprecated-declarations]\n"
        for index in range(UNITS)
    )
    runner = stub_subprocess(
        output=output,
        writes={"--export-fixes": "Diagnostics: []\n", "--analyze": '{"runs": []}'},
    )

    def fake_build(
        *,
        profile: object = None,
        normalizer: Normalizer,
        config: Config,
        subprocess_runner: object = None,
    ) -> tuple[list[Analyzer], list[Limitation]]:
        return build_analyzers(
            profile=profile or load_profile(),  # type: ignore[arg-type]
            normalizer=normalizer,
            config=config,
            subprocess_runner=runner,
        )

    monkeypatch.setattr("caudit.analyzers.service.build_analyzers", fake_build)


def test_a_fifty_unit_scan_stays_inside_its_wall_time_and_token_budget(
    tmp_path: Path, stubbed_diagnostics: None
) -> None:
    """T-12-18: the assembled pipeline, at a size where a regression shows."""
    root, database = generate_tree(tmp_path / "repo", UNITS)
    config = Config.model_validate(
        {
            "cloud_consent": True,
            "index": {"in_process": False},
            "llm": {"triage_enabled": False, "cache_enabled": False},
            "token_budget": {"per_run": BUDGET_TOKENS},
        }
    )
    provider = ScriptedProvider()

    started = time.perf_counter()
    result = run_scan(
        root,
        database,
        config,
        out=tmp_path / "out",
        console=Console(quiet=True),
        provider=provider,
    )
    elapsed = time.perf_counter() - started

    assert elapsed < BUDGET_SECONDS, f"{UNITS} units took {elapsed:.1f}s"
    for name in ("report.md", "results.sarif", "run-manifest.json"):
        assert (tmp_path / "out" / name).is_file()

    manifest = result.artifacts.manifest
    spent = sum(record.input_tokens + record.output_tokens for record in manifest.models)

    # The ceiling stops *further* calls; it cannot un-spend the call that
    # crossed it, so one request's worth of overshoot is by design. What must
    # not happen is spend proportional to the unit count.
    per_call = 1_200
    assert spent <= BUDGET_TOKENS + per_call, f"the run spent {spent} tokens"
    assert spent < UNITS * per_call, "the ceiling did not bind at all"

    # The ledger has to have bound at this size, or the ceiling is untested.
    assert provider.calls < UNITS, "every candidate was adjudicated, so no budget was enforced"

    # Every candidate still reaches the report, including the ones the budget
    # would not pay for — those carry a reason rather than disappearing.
    sections = result.artifacts.sections
    assert len(sections.confirmed) + len(sections.needs_review) == UNITS


def test_the_report_stays_deterministic_at_fifty_units(
    tmp_path: Path, stubbed_diagnostics: None
) -> None:
    """AC-12-7 at a size where a dict-ordering bug would actually surface.

    Three runs, and the first is discarded. AC-12-7 is about two runs with a
    *warm* cache, and the distinction matters here rather than at three units:
    a cached answer costs nothing, so a warm run never reaches the token
    ceiling that stopped the cold run which filled the cache. Comparing a cold
    run against a warm one would be comparing a budget-limited run against an
    unlimited one, which is a real difference and not a determinism failure.
    """
    root, database = generate_tree(tmp_path / "repo", UNITS)
    cache = tmp_path / "llm-cache"
    config = Config.model_validate(
        {
            "cloud_consent": True,
            "llm": {"triage_enabled": False, "cache_enabled": True, "cache_dir": str(cache)},
            "token_budget": {"per_run": BUDGET_TOKENS},
        }
    )

    for name in ("prime", "first", "second"):
        run_scan(
            root,
            database,
            config,
            out=tmp_path / name,
            console=Console(quiet=True),
            provider=ScriptedProvider(),
        )

    for artifact in ("report.md", "results.sarif"):
        assert (tmp_path / "first" / artifact).read_bytes() == (
            tmp_path / "second" / artifact
        ).read_bytes(), artifact
