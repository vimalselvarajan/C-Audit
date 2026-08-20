"""Part 05 integration test: T-05-21.

Every other intake test writes the compilation database by hand, which proves
the parser handles the shapes we *think* CMake emits. This one makes CMake
emit it, so a change in what real tools produce shows up as a failure here
rather than as wrong include paths in a scan.

Deselected by default: it needs a compiler and cmake.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from caudit.intake import load_scan_plan
from tests.conftest import intake_config, write_tree

pytestmark = [pytest.mark.needs_clang, pytest.mark.slow]

PROJECT = {
    "CMakeLists.txt": (
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(caudit_intake_fixture C CXX)\n"
        "set(CMAKE_C_STANDARD 11)\n"
        "set(CMAKE_CXX_STANDARD 17)\n"
        "add_library(fixture STATIC src/alpha.c src/beta.cpp)\n"
        "target_include_directories(fixture PRIVATE include)\n"
    ),
    "include/alpha.h": "#ifndef ALPHA_H\n#define ALPHA_H\nint alpha(int value);\n#endif\n",
    "src/alpha.c": '#include "alpha.h"\n\nint alpha(int value)\n{\n    return value + 1;\n}\n',
    "src/beta.cpp": "int beta(int value)\n{\n    return value * 2;\n}\n",
}


@pytest.fixture
def cmake_project(tmp_path: Path) -> Path:
    if shutil.which("cmake") is None:
        pytest.skip("cmake is not installed; see my_docs/guides/setup.md")
    root = write_tree(tmp_path, PROJECT)
    result = subprocess.run(
        [
            "cmake",
            "-S",
            str(root),
            "-B",
            str(root / "build"),
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DCMAKE_C_COMPILER=clang",
            "-DCMAKE_CXX_COMPILER=clang++",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"cmake configure failed:\n{result.stdout}\n{result.stderr}")
    return root


def test_a_real_cmake_database_loads_completely(cmake_project: Path) -> None:
    """T-05-21: every TU selected, coverage 1.0, no invented flags."""
    database = cmake_project / "build" / "compile_commands.json"
    assert database.is_file(), "cmake did not export a compilation database"

    plan = load_scan_plan(
        cmake_project,
        database,
        intake_config(),
        git_runner=lambda _args, _cwd: None,
    )

    assert [unit.file for unit in plan.units] == [
        PurePosixPath("src/alpha.c"),
        PurePosixPath("src/beta.cpp"),
    ]
    assert plan.excluded == []
    assert plan.coverage.coverage_ratio == 1.0
    assert plan.coverage.tus_selected == plan.coverage.tus_in_database

    languages = {str(unit.file): unit.language for unit in plan.units}
    assert languages == {"src/alpha.c": "c", "src/beta.cpp": "c++"}

    alpha = plan.unit_for("src/alpha.c")
    assert alpha is not None
    # The include path CMake set has to survive intake verbatim: part 06
    # cannot find `alpha.h` without it, and intake must never add one.
    assert any(argument.startswith("-I") for argument in alpha.parse_arguments)
    assert "-c" not in alpha.parse_arguments
    assert "-o" not in alpha.parse_arguments
    assert alpha.directory.is_absolute()
