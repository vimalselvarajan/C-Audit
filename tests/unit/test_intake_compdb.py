"""Part 05 compilation-database tests: T-05-01 … T-05-07, T-05-16.

Every variation the format allows is a real fixture here, because each one is
a place a wrong answer would be silent rather than loud.
"""

from __future__ import annotations

import shutil
from pathlib import Path, PurePosixPath

import pytest

from caudit.cli.main import main
from caudit.errors import IntakeError
from caudit.intake import load_scan_plan
from caudit.intake.compdb import (
    expand_response_files,
    language_of,
    load_entries,
    parse_std,
    setup_recipe,
    split_command,
    standard_is_supported,
    std_argument,
)
from caudit.intake.plan import ExclusionReason, strip_compile_only_flags
from caudit.status import ExitCode
from tests.conftest import FIXTURE_ROOT, compdb_entry, intake_config, write_compdb, write_tree

COMPDB_FIXTURES = FIXTURE_ROOT / "compdb"


def test_command_and_arguments_forms_agree(tmp_path: Path) -> None:
    """T-05-01: one logical entry, two spellings, one TranslationUnit."""
    root = write_tree(tmp_path, {"src/a.c": "int main(void){return 0;}\n"})
    build = str(root / "build")
    absolute = str(root / "src" / "a.c")

    from_command = write_compdb(
        root,
        [compdb_entry(root, absolute, command=f"clang -std=c11 -I../include -c {absolute}")],
        name="command.json",
    )
    from_arguments = write_compdb(
        root,
        [
            compdb_entry(
                root,
                absolute,
                directory=build,
                arguments=["clang", "-std=c11", "-I../include", "-c", absolute],
            )
        ],
        name="arguments.json",
    )

    config = intake_config()
    left = load_scan_plan(root, from_command, config).units
    right = load_scan_plan(root, from_arguments, config).units
    assert left == right
    assert left[0].file == PurePosixPath("src/a.c")
    assert left[0].std == "c11"
    assert left[0].language == "c"


def test_shell_aware_split_preserves_quoted_and_escaped_arguments() -> None:
    """T-05-02: str.split would shatter every path containing a space."""
    command = 'clang -DGREETING="hello world" -I/opt/my\\ libs/include -c "src/a b.c"'
    assert split_command(command) == [
        "clang",
        "-DGREETING=hello world",
        "-I/opt/my libs/include",
        "-c",
        "src/a b.c",
    ]


def test_a_command_with_an_unbalanced_quote_fails_with_the_command_shown() -> None:
    with pytest.raises(IntakeError) as excinfo:
        split_command('clang -DBROKEN="unterminated -c a.c')
    assert "clang -DBROKEN=" in (excinfo.value.hint or "")


def test_relative_file_resolves_against_directory(tmp_path: Path) -> None:
    """T-05-03: `directory: <root>/build`, `file: ../src/a.c` → `src/a.c`."""
    root = write_tree(tmp_path, {"src/a.c": "int main(void){return 0;}\n"})
    database = write_compdb(
        root,
        [
            compdb_entry(
                root,
                "../src/a.c",
                directory=str(root / "build"),
                arguments=["clang", "-c", "../src/a.c"],
            )
        ],
    )
    plan = load_scan_plan(root, database, intake_config())
    assert [unit.file for unit in plan.units] == [PurePosixPath("src/a.c")]
    assert plan.units[0].directory == root / "build"


def test_response_files_are_expanded_inline(tmp_path: Path) -> None:
    """T-05-04: `@flags.rsp` becomes the flags it contains, in place."""
    directory = tmp_path / "build"
    directory.mkdir()
    shutil.copy(COMPDB_FIXTURES / "flags.rsp", directory / "flags.rsp")
    shutil.copy(COMPDB_FIXTURES / "nested.rsp", directory / "nested.rsp")

    expanded = expand_response_files(["clang", "@flags.rsp", "-c", "a.c"], directory)
    assert expanded == ["clang", "-I../include", "-DFEATURE=1", "-Wall", "-c", "a.c"]

    nested = expand_response_files(["clang", "@nested.rsp"], directory)
    assert nested == ["clang", "-DOUTER=1", "-I../include", "-DFEATURE=1", "-Wall"]


def test_a_missing_response_file_stops_rather_than_guessing(tmp_path: Path) -> None:
    with pytest.raises(IntakeError) as excinfo:
        expand_response_files(["clang", "@absent.rsp"], tmp_path)
    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT
    assert "will not continue without them" in (excinfo.value.hint or "")


def test_self_referential_response_file_fails_at_the_depth_cap(tmp_path: Path) -> None:
    """T-05-05: bounded recursion, a clear message, and no infinite loop."""
    shutil.copy(COMPDB_FIXTURES / "loop.rsp", tmp_path / "loop.rsp")
    with pytest.raises(IntakeError) as excinfo:
        expand_response_files(["clang", "@loop.rsp"], tmp_path, max_depth=4)
    assert "depth limit of 4" in excinfo.value.message
    assert "includes itself" in (excinfo.value.hint or "")
    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT


def test_missing_database_exits_environment_with_the_setup_recipe(tmp_path: Path) -> None:
    """T-05-06: the stop names the file and prints the cmake recipe."""
    absent = tmp_path / "build" / "compile_commands.json"
    with pytest.raises(IntakeError) as excinfo:
        load_entries(absent)
    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT
    assert str(absent) in excinfo.value.message
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in (excinfo.value.hint or "")


def test_missing_database_through_the_cli_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-05-06 end to end: the recipe reaches the user's terminal."""
    code = main(["scan", str(tmp_path), "--compile-commands", str(tmp_path / "nope.json")])
    assert code == int(ExitCode.ENVIRONMENT)
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("truncated.json", "not valid JSON"),
        ("empty-array.json", "contains zero entries"),
        ("object-not-array.json", "found a JSON object"),
        ("entries-not-objects.json", "is not an object"),
    ],
)
def test_malformed_databases_are_distinguished(fixture: str, expected: str) -> None:
    """T-05-07: three causes, three messages — they call for different fixes."""
    with pytest.raises(IntakeError) as excinfo:
        load_entries(COMPDB_FIXTURES / fixture)
    assert expected in excinfo.value.message
    assert excinfo.value.exit_code is ExitCode.ENVIRONMENT


def test_an_entry_without_a_command_is_rejected(tmp_path: Path) -> None:
    database = write_compdb(tmp_path, [{"directory": str(tmp_path), "file": "a.c"}])
    with pytest.raises(IntakeError) as excinfo:
        load_entries(database)
    assert "neither 'command' nor 'arguments'" in excinfo.value.message


def test_an_entry_with_a_relative_directory_is_rejected(tmp_path: Path) -> None:
    database = write_compdb(
        tmp_path, [{"directory": "build", "file": "a.c", "command": "clang -c a.c"}]
    )
    with pytest.raises(IntakeError) as excinfo:
        load_entries(database)
    assert "relative 'directory'" in excinfo.value.message


def test_arguments_wins_when_an_entry_carries_both_spellings(tmp_path: Path) -> None:
    """The array form is unambiguous; the string form has been quoted once."""
    database = write_compdb(
        tmp_path,
        [
            {
                "directory": str(tmp_path),
                "file": "a.c",
                "command": "clang -DFROM_COMMAND -c a.c",
                "arguments": ["clang", "-DFROM_ARGUMENTS", "-c", "a.c"],
            }
        ],
    )
    assert load_entries(database)[0].arguments == ("clang", "-DFROM_ARGUMENTS", "-c", "a.c")


@pytest.mark.parametrize(
    ("value", "language", "year", "supported"),
    [
        ("c11", "c", 11, True),
        ("gnu11", "c", 11, True),
        ("c17", "c", 17, True),
        ("c2x", "c", 20, True),
        ("c23", "c", 23, True),
        ("c99", "c", 99, False),
        ("gnu89", "c", 89, False),
        ("c++17", "c++", 17, True),
        ("gnu++17", "c++", 17, True),
        ("c++20", "c++", 20, True),
        ("c++2b", "c++", 20, True),
        ("c++11", "c++", 11, False),
        ("c++98", "c++", 98, False),
        ("iso9899:2011", "c", 11, True),
        ("iso9899:1999", "c", 99, False),
    ],
)
def test_standard_parsing(value: str, language: str, year: int, supported: bool) -> None:
    """T-05-16, first half: the dialect table, one row at a time."""
    info = parse_std(value)
    assert info.language == language
    assert info.year == year
    assert standard_is_supported(info) is supported


def test_an_unrecognized_standard_is_not_judged() -> None:
    """Refusing to scan a dialect we merely failed to parse is the worse error."""
    info = parse_std("borland7")
    assert not info.recognized
    assert standard_is_supported(info) is True


def test_language_from_dash_x_beats_the_extension() -> None:
    assert language_of(["clang", "-x", "c++", "-c", "a.c"], "a.c") == "c++"
    assert language_of(["clang", "-xc++", "-c", "a.c"], "a.c") == "c++"
    assert language_of(["clang", "-c", "a.cc"], "a.cc") == "c++"
    assert language_of(["clang", "-c", "a.c"], "a.c") == "c"
    assert language_of(["clang", "-x", "objective-c", "-c", "a.m"], "a.m") is None
    assert language_of(["clang", "-c", "a.rs"], "a.rs") is None


def test_the_last_std_flag_wins_as_it_does_in_the_driver() -> None:
    assert std_argument(["clang", "-std=c99", "-std=c11"]) == "c11"
    assert std_argument(["clang", "--std=c++20"]) == "c++20"
    assert std_argument(["clang", "-c", "a.c"]) is None


def test_standards_and_languages_across_a_whole_database(tmp_path: Path) -> None:
    """T-05-16: `-std=c++17`, `-std=c99`, `-x c++`, bare `.cc`, in one plan."""
    root = write_tree(
        tmp_path,
        {
            "src/modern.cpp": "void a(){}\n",
            "src/legacy.c": "void b(void){}\n",
            "src/forced.c": "void c(void){}\n",
            "src/bare.cc": "void d(){}\n",
        },
    )
    database = write_compdb(
        root,
        [
            compdb_entry(
                root,
                str(root / "src/modern.cpp"),
                arguments=["clang++", "-std=c++17", "-c", str(root / "src/modern.cpp")],
            ),
            compdb_entry(
                root,
                str(root / "src/legacy.c"),
                arguments=["clang", "-std=c99", "-c", str(root / "src/legacy.c")],
            ),
            compdb_entry(
                root,
                str(root / "src/forced.c"),
                arguments=["clang", "-x", "c++", "-c", str(root / "src/forced.c")],
            ),
            compdb_entry(
                root,
                str(root / "src/bare.cc"),
                arguments=["clang++", "-c", str(root / "src/bare.cc")],
            ),
        ],
    )
    plan = load_scan_plan(root, database, intake_config())
    units = {str(unit.file): unit for unit in plan.units}

    assert units["src/modern.cpp"].language == "c++"
    assert units["src/modern.cpp"].std == "c++17"
    assert units["src/forced.c"].language == "c++"
    assert units["src/bare.cc"].language == "c++"
    assert units["src/bare.cc"].std is None

    assert "src/legacy.c" not in units
    assert plan.excluded_by(ExclusionReason.UNSUPPORTED_LANGUAGE) == [PurePosixPath("src/legacy.c")]


def test_compile_only_flags_are_stripped_for_parsing_but_kept_on_the_record() -> None:
    arguments = [
        "clang",
        "-std=c11",
        "-I/inc",
        "-c",
        "-o",
        "build/a.o",
        "-MD",
        "-MFbuild/a.d",
        "-MT",
        "build/a.o",
        "src/a.c",
    ]
    assert strip_compile_only_flags(arguments) == ["clang", "-std=c11", "-I/inc", "src/a.c"]


def test_the_setup_recipe_names_every_supported_build_system() -> None:
    recipe = setup_recipe(Path("build/compile_commands.json"))
    for expected in ("cmake", "bear", "compiledb", "JSONCompilationDatabase"):
        assert expected in recipe
