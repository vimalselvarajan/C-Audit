"""Part 01 toolchain tests: T-01-02 … T-01-05, T-01-14."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from caudit.cli.main import main
from caudit.config.toolchain import (
    ToolchainProbe,
    ToolStatus,
    VersionSpec,
    parse_version,
    requirements_for,
)
from caudit.errors import ToolchainError
from caudit.status import ExitCode


def _fake_which(available: dict[str, str]):  # type: ignore[no-untyped-def]
    def which(name: str, _path: str | None = None) -> str | None:
        return available.get(name)

    return which


def _fake_runner(outputs: dict[str, str]):  # type: ignore[no-untyped-def]
    def runner(path: Path, _args: Sequence[str]) -> str:
        return outputs.get(path.name, "")

    return runner


ALL_TOOLS = ("clang", "clang++", "clang-tidy", "scan-build", "clang-format")


def test_all_tools_present_and_satisfied() -> None:
    """T-01-02: doctor reports all satisfied when every pin is met."""
    available = {name: f"/usr/bin/{name}" for name in ALL_TOOLS}
    outputs = dict.fromkeys(ALL_TOOLS, "Ubuntu clang version 18.1.3 (1ubuntu1)")
    probe = ToolchainProbe(
        which=_fake_which(available), runner=_fake_runner(outputs), llvm_major=18
    )
    infos = probe.probe(requirements_for(18))
    assert [info.name for info in infos] == list(ALL_TOOLS)
    assert all(info.satisfies_requirement for info in infos)
    assert all(info.version == "18.1.3" for info in infos)
    probe.require("clang", "clang-tidy")  # does not raise


def test_empty_path_lists_every_tool_as_missing_with_an_install_command() -> None:
    """T-01-03: every missing tool is named with a copy-pasteable command."""
    probe = ToolchainProbe(which=_fake_which({}), runner=_fake_runner({}), llvm_major=18)
    infos = probe.probe(requirements_for(18))
    assert all(info.status is ToolStatus.MISSING for info in infos)
    assert all(not info.satisfies_requirement for info in infos)
    for info in infos:
        assert "apt-get install" in info.install_hint
        assert "18" in info.install_hint


def test_doctor_on_a_machine_with_no_clang_exits_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-01-03: the real CLI path, no traceback, exit 3."""
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr("shutil.which", lambda _name, **_kwargs: None)
    code = main(["doctor"])
    captured = capsys.readouterr()
    assert code == ExitCode.ENVIRONMENT
    assert "apt-get install" in captured.out
    assert "my_docs/guides/setup.md" in captured.out
    assert "Traceback" not in captured.err


def test_version_below_the_pin_is_unsatisfied_and_names_both_versions() -> None:
    """T-01-04: clang-tidy 15 against a pin of 18."""
    probe = ToolchainProbe(
        which=_fake_which({"clang-tidy": "/usr/bin/clang-tidy"}),
        runner=_fake_runner({"clang-tidy": "LLVM version 15.0.7"}),
        llvm_major=18,
    )
    (info,) = probe.probe({"clang-tidy": requirements_for(18)["clang-tidy"]})
    assert not info.satisfies_requirement
    assert info.status is ToolStatus.OUT_OF_RANGE
    assert "15.0.7" in info.detail
    assert "18" in info.detail

    with pytest.raises(ToolchainError) as excinfo:
        probe.require("clang-tidy")
    assert "15.0.7" in str(excinfo.value)


def test_unparseable_version_is_unknown_and_unsatisfied_without_raising() -> None:
    """T-01-05: no exception, version recorded as unknown."""
    probe = ToolchainProbe(
        which=_fake_which({"clang-tidy": "/usr/bin/clang-tidy"}),
        runner=_fake_runner({"clang-tidy": "this build has no version banner"}),
        llvm_major=18,
    )
    (info,) = probe.probe({"clang-tidy": requirements_for(18)["clang-tidy"]})
    assert info.version is None
    assert info.version_display == "unknown"
    assert not info.satisfies_requirement
    assert info.status is ToolStatus.UNPARSEABLE_VERSION


def test_scan_build_is_satisfied_by_presence_alone() -> None:
    """scan-build has no version flag; presence is the honest check."""
    probe = ToolchainProbe(
        which=_fake_which({"scan-build": "/usr/bin/scan-build"}),
        runner=_fake_runner({"scan-build": "USAGE: scan-build [options] <build command>"}),
        llvm_major=18,
    )
    (info,) = probe.probe({"scan-build": requirements_for(18)["scan-build"]})
    assert info.satisfies_requirement
    assert info.version is None


def test_probe_failure_is_reported_not_raised() -> None:
    def runner(_path: Path, _args: Sequence[str]) -> str:
        raise OSError("permission denied")

    probe = ToolchainProbe(
        which=_fake_which({"clang": "/usr/bin/clang"}), runner=runner, llvm_major=18
    )
    (info,) = probe.probe({"clang": requirements_for(18)["clang"]})
    assert info.status is ToolStatus.PROBE_FAILED
    assert not info.satisfies_requirement


def test_wheel_and_clang_tidy_major_drift_is_reported() -> None:
    """Part 01 risk: differing majors can produce subtly different ASTs."""
    probe = ToolchainProbe(
        which=_fake_which({"clang-tidy": "/usr/bin/clang-tidy"}),
        runner=_fake_runner({"clang-tidy": "LLVM version 19.1.0"}),
        llvm_major=19,
    )
    infos = probe.probe_defaults()
    wheel = next(i for i in infos if i.name.startswith("libclang"))
    assert "major differs from clang-tidy" in wheel.detail


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Ubuntu clang version 18.1.3 (1ubuntu1)", "18.1.3"),
        ("LLVM (http://llvm.org/):\n  LLVM version 18.1.8", "18.1.8"),
        ("clang version 20.0.0git", "20.0.0"),
        ("no version here", None),
    ],
)
def test_parse_version(text: str, expected: str | None) -> None:
    assert parse_version(text) == expected


def test_version_spec_range() -> None:
    spec = VersionSpec(min_major=18, max_major=20)
    assert spec.satisfied_by("18.1.3")
    assert spec.satisfied_by("20.0.0")
    assert not spec.satisfied_by("17.9.9")
    assert not spec.satisfied_by("21.0.0")
    assert not spec.satisfied_by(None)
    assert spec.describe() == "18-20"


@pytest.mark.needs_clang
def test_doctor_finds_a_real_clang_tidy() -> None:
    """T-01-14: against a real toolchain, the true version parses."""
    probe = ToolchainProbe(llvm_major=18)
    (info,) = probe.probe({"clang-tidy": requirements_for(18)["clang-tidy"]})
    assert info.path is not None
    assert info.version is not None
    assert info.satisfies_requirement
