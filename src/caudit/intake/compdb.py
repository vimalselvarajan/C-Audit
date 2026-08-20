"""Loading and normalizing a Clang JSON compilation database.

The `format <https://clang.llvm.org/docs/JSONCompilationDatabase.html>`_ has
more variation than it looks: two spellings of the command, paths relative to
a per-entry working directory, response files, and one file compiled several
times by a multi-config build. Each of those is a place where a wrong answer
is silent — the wrong include path produces a plausible index of the wrong
code — so each is handled explicitly and none is guessed.

Failures here stop the run. That is the point of the part: the alternative to
stopping is inventing flags.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

from caudit.errors import IntakeError
from caudit.intake.plan import Language

__all__ = [
    "HEADER_EXTENSIONS",
    "SOURCE_EXTENSIONS",
    "SUPPORTED_CXX_STANDARDS",
    "SUPPORTED_C_STANDARDS",
    "RawEntry",
    "StdInfo",
    "expand_response_files",
    "is_header_file",
    "is_implementation_file",
    "iter_source_files",
    "language_of",
    "load_entries",
    "parse_std",
    "setup_recipe",
    "split_command",
    "standard_is_supported",
    "std_argument",
]

#: Extension to language. Case-sensitive: on a POSIX filesystem ``.C`` is C++
#: and ``.c`` is C, and conflating them changes how the file parses.
SOURCE_EXTENSIONS: Final[dict[str, Language]] = {
    ".c": "c",
    ".cc": "c++",
    ".cp": "c++",
    ".cpp": "c++",
    ".cxx": "c++",
    ".c++": "c++",
    ".C": "c++",
    ".CPP": "c++",
    ".ii": "c++",
    ".i": "c",
}

#: Headers are reached through the units that include them (part 06). They
#: are never invented as units here and never counted in coverage.
HEADER_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".h", ".hh", ".hpp", ".hxx", ".h++", ".H", ".inc", ".ipp", ".tcc"}
)

#: ``-x`` values that map onto a language we handle. Anything else (Objective-C,
#: CUDA, assembler) is out of scope and is excluded rather than mis-parsed.
_X_LANGUAGES: Final[dict[str, Language]] = {
    "c": "c",
    "c-header": "c",
    "cpp-output": "c",
    "c++": "c++",
    "c++-header": "c++",
    "c++-cpp-output": "c++",
}

#: The MVP is scoped to C11 and later, C++17 and later.
SUPPORTED_C_STANDARDS: Final[int] = 11
SUPPORTED_CXX_STANDARDS: Final[int] = 17

#: ``iso9899:`` spellings clang accepts, mapped to the short year.
_ISO_C_YEARS: Final[dict[str, int]] = {
    "1990": 90,
    "199409": 94,
    "1999": 99,
    "199x": 99,
    "2011": 11,
    "2017": 17,
    "2018": 17,
}

#: A response file that expands to more than this is treated as hostile rather
#: than merely large.
_MAX_EXPANDED_ARGUMENTS: Final[int] = 100_000


def setup_recipe(compdb: Path | None = None) -> str:
    """The instructions every hard stop prints. One wording, one place."""
    target = compdb.name if compdb is not None else "compile_commands.json"
    return (
        "C Audit does not guess include paths or compiler flags. Generate a real\n"
        "compilation database and point at it:\n"
        "\n"
        "  CMake:   cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON\n"
        "  Make:    bear -- make\n"
        "  Other:   compiledb make\n"
        "\n"
        f"then re-run with --compile-commands <path to {target}>.\n"
        "Format reference: https://clang.llvm.org/docs/JSONCompilationDatabase.html"
    )


@dataclass(frozen=True)
class RawEntry:
    """One database entry, normalized but not yet judged.

    ``index`` is the position in the file. Duplicate resolution is "last entry
    wins", so the position is what makes that deterministic rather than
    dependent on dict ordering.
    """

    index: int
    file: str
    directory: Path
    arguments: tuple[str, ...]
    output: str | None

    @property
    def absolute_file(self) -> Path:
        """``file`` resolved against ``directory``, as the format specifies."""
        candidate = Path(self.file)
        if not candidate.is_absolute():
            candidate = self.directory / candidate
        return Path(candidate).resolve()


def split_command(command: str) -> list[str]:
    """Shell-aware split of the ``command`` string form.

    ``str.split()`` would break every path containing a space, and quoted
    ``-D`` values are common in real databases.
    """
    try:
        return shlex.split(command, posix=True)
    except ValueError as exc:
        raise IntakeError(
            f"could not split the compile command: {exc}",
            hint=f"The offending command was:\n  {command}",
        ) from exc


def _read_response_file(path: Path, referenced_by: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise IntakeError(
            f"response file {path} could not be read: {exc}",
            hint=(
                f"It is referenced from {referenced_by}. Its flags are unknown, and "
                "C Audit will not continue without them.\n\n" + setup_recipe()
            ),
        ) from exc


def expand_response_files(
    arguments: Sequence[str], directory: Path, *, max_depth: int = 8, _depth: int = 0
) -> list[str]:
    """Replace every ``@file`` with its contents, recursively.

    Response files are resolved against ``directory`` — the entry's working
    directory — because that is the compiler's own rule. Recursion is bounded
    by ``max_depth``: a response file that includes itself fails there instead
    of spinning.
    """
    if _depth > max_depth:
        raise IntakeError(
            f"response file expansion exceeded the depth limit of {max_depth}",
            hint=(
                "A response file almost certainly includes itself, directly or through "
                "another. Fix the build, or raise intake.response_file_depth if the "
                "nesting is genuine."
            ),
        )

    expanded: list[str] = []
    for argument in arguments:
        if not argument.startswith("@") or len(argument) == 1:
            expanded.append(argument)
            continue
        reference = Path(argument[1:])
        target = reference if reference.is_absolute() else directory / reference
        contents = _read_response_file(target, directory)
        nested = shlex.split(contents, posix=True)
        expanded.extend(
            expand_response_files(nested, directory, max_depth=max_depth, _depth=_depth + 1)
        )
        if len(expanded) > _MAX_EXPANDED_ARGUMENTS:
            raise IntakeError(
                f"response file expansion produced more than {_MAX_EXPANDED_ARGUMENTS} arguments",
                hint=f"Expansion started at {target}.",
            )
    return expanded


def _entry_arguments(raw: dict[str, Any], index: int, path: Path) -> list[str]:
    """The argv for one entry, from whichever spelling it uses.

    ``arguments`` wins when both are present: it is unambiguous, where the
    string form has already been through one round of shell quoting.
    """
    arguments = raw.get("arguments")
    if arguments is not None:
        if not isinstance(arguments, list) or not all(isinstance(a, str) for a in arguments):
            raise IntakeError(
                f"{path}: entry {index} has an 'arguments' field that is not a list of strings",
                hint=setup_recipe(path),
            )
        if not arguments:
            raise IntakeError(
                f"{path}: entry {index} has an empty 'arguments' list",
                hint=setup_recipe(path),
            )
        return list(arguments)

    command = raw.get("command")
    if isinstance(command, str) and command.strip():
        split = split_command(command)
        if not split:
            raise IntakeError(
                f"{path}: entry {index} has an empty 'command'", hint=setup_recipe(path)
            )
        return split

    raise IntakeError(
        f"{path}: entry {index} has neither 'command' nor 'arguments'",
        hint=(
            "Every entry must carry the compile command. Without it the flags are "
            "unknown.\n\n" + setup_recipe(path)
        ),
    )


def _decode(path: Path) -> Any:
    if not path.exists():
        raise IntakeError(
            f"compilation database not found: {path}",
            hint=setup_recipe(path),
        )
    if not path.is_file():
        raise IntakeError(
            f"compilation database is not a regular file: {path}",
            hint=setup_recipe(path),
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise IntakeError(f"compilation database {path} could not be read: {exc}") from exc
    if not text.strip():
        raise IntakeError(
            f"compilation database {path} is empty",
            hint=setup_recipe(path),
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntakeError(
            f"compilation database {path} is not valid JSON: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})",
            hint=(
                "The file is truncated or corrupt. Regenerate it rather than editing "
                "it by hand.\n\n" + setup_recipe(path)
            ),
        ) from exc


def _required_string(raw: dict[str, Any], name: str, index: int, path: Path) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value.strip():
        raise IntakeError(
            f"{path}: entry {index} is missing a usable '{name}' field",
            hint=setup_recipe(path),
        )
    return value


def load_entries(path: Path, *, response_file_depth: int = 8) -> list[RawEntry]:
    """Parse a compilation database into normalized entries.

    Raises :class:`~caudit.errors.IntakeError` — exit ``ENVIRONMENT`` — when
    the file is missing, unparseable, empty, or not an array of entries. The
    three causes produce three different messages, because "your JSON is
    truncated" and "your build produced no entries" call for different fixes.
    """
    decoded = _decode(path)
    if not isinstance(decoded, list):
        found = type(decoded).__name__
        shape = "a JSON object" if isinstance(decoded, dict) else f"a JSON {found}"
        raise IntakeError(
            f"compilation database {path} must be a JSON array of entries, found {shape}",
            hint=setup_recipe(path),
        )
    if not decoded:
        raise IntakeError(
            f"compilation database {path} contains zero entries",
            hint=(
                "The build produced a database but compiled nothing. Build the project "
                "first, then regenerate it.\n\n" + setup_recipe(path)
            ),
        )

    entries: list[RawEntry] = []
    for index, raw in enumerate(decoded):
        if not isinstance(raw, dict):
            raise IntakeError(f"{path}: entry {index} is not an object", hint=setup_recipe(path))
        file_field = _required_string(raw, "file", index, path)
        directory_field = _required_string(raw, "directory", index, path)
        directory = Path(directory_field)
        if not directory.is_absolute():
            raise IntakeError(
                f"{path}: entry {index} has a relative 'directory' ({directory_field}); "
                "the format requires an absolute working directory",
                hint=setup_recipe(path),
            )
        arguments = expand_response_files(
            _entry_arguments(raw, index, path), directory, max_depth=response_file_depth
        )
        output = raw.get("output")
        entries.append(
            RawEntry(
                index=index,
                file=file_field,
                directory=directory,
                arguments=tuple(arguments),
                output=output if isinstance(output, str) else None,
            )
        )
    return entries


@dataclass(frozen=True)
class StdInfo:
    """A parsed ``-std=`` value."""

    #: As written, lowercased.
    raw: str
    language: Language | None
    #: Two- or four-digit year as the standard names it: 99, 11, 17, 20, 23.
    year: int | None

    @property
    def recognized(self) -> bool:
        return self.language is not None and self.year is not None


def parse_std(value: str) -> StdInfo:
    """Read ``c11``, ``gnu++20``, ``iso9899:1999`` into a language and a year.

    An unrecognized value yields ``recognized == False``. Callers keep such a
    unit and record the ambiguity: refusing to scan a dialect we merely failed
    to parse would be a worse error than scanning it.
    """
    text = value.strip().lower()
    if text.startswith("iso9899:"):
        year = _ISO_C_YEARS.get(text.split(":", 1)[1])
        return StdInfo(raw=text, language="c" if year is not None else None, year=year)

    body = text
    for prefix in ("gnu", "c"):
        if body.startswith(prefix):
            body = body[len(prefix) :]
            break
    else:
        return StdInfo(raw=text, language=None, year=None)

    language: Language = "c"
    if body.startswith("++"):
        language = "c++"
        body = body[2:]

    year = _year_of(body)
    if year is None:
        return StdInfo(raw=text, language=None, year=None)
    return StdInfo(raw=text, language=language, year=year)


def _year_of(body: str) -> int | None:
    """``17`` → 17, ``2x`` → 20-something, ``1z`` → 19-something."""
    if body.isdigit() and len(body) in (2, 4):
        number = int(body)
        return number % 100 if len(body) == 4 else number
    # Draft spellings: c2x, c++1z, c++2b. The decade is what matters for a
    # minimum-version check, so the letter rounds down to the decade start.
    if len(body) == 2 and body[0].isdigit() and body[1].isalpha():
        return int(body[0]) * 10
    return None


def standard_is_supported(info: StdInfo) -> bool:
    """C11+ or C++17+. An unrecognized standard is not judged here."""
    if info.year is None:
        return True
    if info.language == "c++":
        return _normalize_cxx_year(info.year) >= SUPPORTED_CXX_STANDARDS
    return _normalize_c_year(info.year) >= SUPPORTED_C_STANDARDS


def _normalize_c_year(year: int) -> int:
    """C89/C90/C94/C99 are the 20th-century standards; everything else is later."""
    return -1 if year >= 80 else year


def _normalize_cxx_year(year: int) -> int:
    """C++98 and C++03 predate the supported range; 11, 14, 17, 20, 23 follow it."""
    return -1 if year >= 90 else year


def language_of(arguments: Sequence[str], file: str) -> Language | None:
    """The language from ``-x``, else the extension. ``None`` when out of scope."""
    explicit = _explicit_language(arguments)
    if explicit is not None:
        return explicit[0]
    return SOURCE_EXTENSIONS.get(Path(file).suffix)


def _explicit_language(arguments: Sequence[str]) -> tuple[Language | None, str] | None:
    """``(language, raw)`` for the last ``-x``, or ``None`` if there was none.

    The language is ``None`` when ``-x`` named something real that we do not
    handle, which is a different answer from "not specified".
    """
    found: tuple[Language | None, str] | None = None
    for index, argument in enumerate(arguments):
        raw: str | None = None
        if argument == "-x" and index + 1 < len(arguments):
            raw = arguments[index + 1]
        elif argument.startswith("-x") and len(argument) > 2:
            raw = argument[2:]
        if raw is not None:
            found = (_X_LANGUAGES.get(raw.strip().lower()), raw.strip().lower())
    return found


def std_argument(arguments: Sequence[str]) -> str | None:
    """The last ``-std=`` value, or ``None``. Later flags win, as in the driver."""
    found: str | None = None
    for argument in arguments:
        if argument.startswith("-std="):
            found = argument[len("-std=") :].strip().lower()
        elif argument.startswith("--std="):
            found = argument[len("--std=") :].strip().lower()
    return found or None


def is_implementation_file(path: PurePosixPath | Path | str) -> bool:
    """True for a file that can be a translation unit on its own."""
    return Path(str(path)).suffix in SOURCE_EXTENSIONS


def is_header_file(path: PurePosixPath | Path | str) -> bool:
    return Path(str(path)).suffix in HEADER_EXTENSIONS


def iter_source_files(root: Path, skip_dirs: frozenset[str]) -> Iterator[Path]:
    """Every implementation file under ``root``, not descending into ``skip_dirs``.

    Directories are pruned rather than filtered afterwards: walking a vendored
    ``node_modules`` to then discard it is the difference between a fast intake
    and a slow one on a real repository.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = sorted(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name in skip_dirs or child.name.startswith("."):
                    continue
                stack.append(child)
            elif is_implementation_file(child):
                yield child
