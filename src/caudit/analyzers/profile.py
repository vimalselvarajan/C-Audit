"""The curated check profile: which checks run, and what each one feeds.

The profile is committed configuration with its own version string, recorded
in the manifest so a report can name the ruleset that produced it. Two rules
give it teeth:

* **Every check is annotated with the weakness families it feeds.** A check
  with no annotation is a validation error naming the check, not a warning —
  an unannotated rule would fire into part 04's metrics without landing in any
  family, and the profile could then never be tuned with data.
* **A CWE mapping is optional and often absent.** An analyzer rule whose
  accurate CWE is not obvious maps to nothing, and the candidate it produces
  carries ``suggested_cwe=[]`` and is routed to review. Guessing here would
  put an invented classification into a report.

Two spellings of one check are reconciled rather than duplicated. clang-tidy
re-reports the static analyzer as ``clang-analyzer-<checker>`` and the
compiler as ``clang-diagnostic-<warning>``; :meth:`CheckProfile.lookup`
rewrites both back to the profile's own spelling, so one warning has one CWE
regardless of which producer surfaced it.

The file ships inside the package (``caudit/config/profiles/``) rather than at
the repository root, so an installed wheel carries the ruleset it was built
with. The plan's path is ``config/profiles/security.yaml``; this is that file,
inside the ``config`` package that part 01 owns.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import yaml

from caudit.errors import ConfigError
from caudit.model.cwe import WeaknessFamily, is_cwe_id

__all__ = [
    "MAINTAINABILITY",
    "PROFILE_DIR",
    "Check",
    "CheckProfile",
    "load_profile",
    "weakness_families_of",
]

PROFILE_DIR: Final = Path(__file__).resolve().parents[1] / "config" / "profiles"

#: The seventh annotation. Not a weakness family: it marks the narrow
#: `readability-*`/`misc-*` slice the spec keeps for security-relevant
#: maintainability signals, which never produce a vulnerability claim.
MAINTAINABILITY: Final = "maintainability"

_VALID_FAMILIES: Final[frozenset[str]] = frozenset(
    {family.value for family in WeaknessFamily} | {MAINTAINABILITY}
)

#: clang-tidy's prefixes for checks it does not own. Stripping them is a
#: naming convention of clang-tidy's, not an inference about semantics.
_TIDY_ANALYZER_PREFIX: Final = "clang-analyzer-"
_TIDY_DIAGNOSTIC_PREFIX: Final = "clang-diagnostic-"


class ProfileError(ConfigError):
    """The profile is missing, unreadable, or fails validation."""


class Check:
    """One check, its enablement, and what it feeds.

    ``id`` is either an exact rule id or a trailing-``*`` glob. Exact wins over
    glob, and a longer glob wins over a shorter one, so ``bugprone-*`` is a
    default that a named entry underneath it overrides.
    """

    __slots__ = ("cwe", "enabled", "families", "id", "note", "producer")

    def __init__(
        self,
        *,
        check_id: str,
        families: Sequence[str],
        producer: str,
        cwe: Sequence[str] = (),
        enabled: bool = True,
        note: str = "",
    ) -> None:
        self.id = check_id
        self.families = tuple(families)
        self.producer = producer
        self.cwe = tuple(cwe)
        self.enabled = enabled
        self.note = note

    @property
    def is_glob(self) -> bool:
        return self.id.endswith("*")

    @property
    def prefix(self) -> str:
        """The literal part of a glob; the whole id for an exact check."""
        return self.id[:-1] if self.is_glob else self.id

    def matches(self, rule_id: str) -> bool:
        return rule_id.startswith(self.prefix) if self.is_glob else rule_id == self.id

    def weakness_families(self) -> tuple[WeaknessFamily, ...]:
        """The annotated families, minus the maintainability marker."""
        return weakness_families_of(self.families)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Check({self.id!r}, families={self.families!r}, enabled={self.enabled})"


def weakness_families_of(families: Iterable[str]) -> tuple[WeaknessFamily, ...]:
    """Parse annotations into families, dropping ``maintainability``."""
    return tuple(WeaknessFamily(name) for name in families if name != MAINTAINABILITY)


class CheckProfile:
    """A loaded, validated profile.

    Lookup is by rule id across *all* producers rather than per producer. The
    same check reaches C Audit under two names depending on whether clang-tidy
    or the analyzer itself reported it, and a per-producer table would give the
    two spellings two different CWEs.
    """

    def __init__(
        self,
        *,
        version: str,
        name: str,
        checks: Sequence[Check],
        diagnostic_flags: Sequence[str] = (),
        diagnostic_format: str = "text",
        description: str = "",
        source: Path | None = None,
    ) -> None:
        self.version = version
        self.name = name
        self.checks = tuple(checks)
        self.diagnostic_flags = tuple(diagnostic_flags)
        self.diagnostic_format = diagnostic_format
        self.description = description
        self.source = source
        self._exact: dict[str, Check] = {c.id: c for c in checks if not c.is_glob}
        # Longest prefix first, so a named entry beats the glob above it.
        self._globs: tuple[Check, ...] = tuple(
            sorted((c for c in checks if c.is_glob), key=lambda c: len(c.prefix), reverse=True)
        )

    # --------------------------------------------------------------- lookup

    def lookup(self, rule_id: str) -> Check | None:
        """The check governing ``rule_id``, under any of its spellings.

        ``None`` for a rule the profile has never heard of — a newly added
        upstream check, say. That is not an error: the candidate is still
        produced, with no CWE, and routed to review.
        """
        for candidate in self._aliases(rule_id):
            exact = self._exact.get(candidate)
            if exact is not None:
                return exact
        for candidate in self._aliases(rule_id):
            for glob in self._globs:
                if glob.matches(candidate):
                    return glob
        return None

    def cwe_for(self, rule_id: str) -> list[str]:
        """Suggested CWEs for a rule. Empty when nothing accurate is known."""
        check = self.lookup(rule_id)
        return list(check.cwe) if check is not None else []

    def families_for(self, rule_id: str) -> tuple[WeaknessFamily, ...]:
        check = self.lookup(rule_id)
        return check.weakness_families() if check is not None else ()

    @staticmethod
    def _aliases(rule_id: str) -> tuple[str, ...]:
        """Every spelling of one check, most specific first.

        ``clang-analyzer-unix.Malloc`` is ``unix.Malloc``;
        ``clang-diagnostic-format-security`` is ``-Wformat-security``. Both
        rewrites are clang-tidy's own naming convention.
        """
        if rule_id.startswith(_TIDY_ANALYZER_PREFIX):
            return (rule_id, rule_id[len(_TIDY_ANALYZER_PREFIX) :])
        if rule_id.startswith(_TIDY_DIAGNOSTIC_PREFIX):
            return (rule_id, "-W" + rule_id[len(_TIDY_DIAGNOSTIC_PREFIX) :])
        if rule_id.startswith("-W"):
            return (rule_id, _TIDY_DIAGNOSTIC_PREFIX + rule_id[2:])
        # Only a dotted, unprefixed name is a static-analyzer checker. Adding
        # the prefix to anything else would make every unknown clang-tidy check
        # match `clang-analyzer-*` and inherit a mapping it has no claim to.
        if "." in rule_id and not rule_id.startswith("-"):
            return (rule_id, _TIDY_ANALYZER_PREFIX + rule_id)
        return (rule_id,)

    # ------------------------------------------------------------ selection

    def checks_for(self, producer: str, *, enabled_only: bool = True) -> list[Check]:
        return [
            check
            for check in self.checks
            if check.producer == producer and (check.enabled or not enabled_only)
        ]

    def csa_checkers(self) -> list[str]:
        """Checker ids to pass as ``-analyzer-checker``, sorted."""
        return sorted(check.id for check in self.checks_for("csa"))

    def tidy_checks_argument(self) -> str:
        """The ``--checks=`` value: everything off, then the profile back on.

        Disabled entries are emitted as explicit negations after the
        enablements, because clang-tidy applies the list in order.
        """
        enabled = sorted(check.id for check in self.checks_for("tidy"))
        disabled = sorted(
            check.id for check in self.checks_for("tidy", enabled_only=False) if not check.enabled
        )
        return ",".join(["-*", *enabled, *(f"-{check}" for check in disabled)])

    def families_covered(self) -> set[WeaknessFamily]:
        """Every in-scope family at least one enabled check feeds."""
        return {
            family for check in self.checks if check.enabled for family in check.weakness_families()
        }

    def describe(self) -> str:
        enabled = sum(1 for check in self.checks if check.enabled)
        return f"{self.name} v{self.version} ({enabled}/{len(self.checks)} checks enabled)"


# ---------------------------------------------------------------- loading


def load_profile(name_or_path: str = "security") -> CheckProfile:
    """Load a profile by packaged name or by path.

    A bare name resolves inside the packaged profile directory. Anything
    containing a separator or a ``.yaml`` suffix is a path, so a user can pin
    their own ruleset without editing the package.
    """
    path = _resolve(name_or_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(
            f"could not read the check profile {path}: {exc}",
            hint="Set analyzers.profile to a packaged name or an existing YAML file.",
        ) from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileError(f"{path} is not valid YAML: {exc}") from exc
    return parse_profile(raw, source=path)


def _resolve(name_or_path: str) -> Path:
    if name_or_path.endswith((".yaml", ".yml")) or "/" in name_or_path or "\\" in name_or_path:
        return Path(name_or_path).expanduser()
    candidate = PROFILE_DIR / f"{name_or_path}.yaml"
    if not candidate.is_file():
        available = ", ".join(sorted(p.stem for p in PROFILE_DIR.glob("*.yaml"))) or "none"
        raise ProfileError(
            f"no packaged check profile named '{name_or_path}' (available: {available})"
        )
    return candidate


def parse_profile(raw: object, *, source: Path | None = None) -> CheckProfile:
    """Validate a parsed profile document. Raises :class:`ProfileError`."""
    where = str(source) if source is not None else "<profile>"
    if not isinstance(raw, dict):
        raise ProfileError(f"{where}: a profile must be a mapping, got {type(raw).__name__}")

    version = raw.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ProfileError(
            f"{where}: a profile needs a non-empty 'version' string; it is recorded in "
            "the run manifest so a report can name the ruleset that produced it"
        )

    diagnostics = _section(raw, "diagnostics", where)
    checks: list[Check] = []
    for producer in ("diagnostics", "csa", "tidy"):
        section = _section(raw, producer, where)
        checks.extend(_parse_checks(section.get("checks"), producer=producer, where=where))
    _reject_duplicates(checks, where)

    fmt = diagnostics.get("format", "text")
    if fmt not in {"text", "json"}:
        raise ProfileError(f"{where}: diagnostics.format must be 'text' or 'json', got {fmt!r}")

    return CheckProfile(
        version=version.strip(),
        name=str(raw.get("name") or (source.stem if source else "profile")),
        checks=checks,
        diagnostic_flags=_string_list(diagnostics.get("flags"), "diagnostics.flags", where),
        diagnostic_format=fmt,
        description=str(raw.get("description") or "").strip(),
        source=source,
    )


def _section(raw: Mapping[str, Any], key: str, where: str) -> dict[str, Any]:
    value = raw.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProfileError(f"{where}: '{key}' must be a mapping, got {type(value).__name__}")
    return value


def _parse_checks(raw: object, *, producer: str, where: str) -> list[Check]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError(f"{where}: {producer}.checks must be a list")
    return [
        _parse_check(entry, producer=producer, where=where, position=n)
        for n, entry in enumerate(raw)
    ]


def _parse_check(entry: object, *, producer: str, where: str, position: int) -> Check:
    if not isinstance(entry, dict):
        raise ProfileError(f"{where}: {producer}.checks[{position}] must be a mapping")
    check_id = entry.get("id")
    if not isinstance(check_id, str) or not check_id.strip():
        raise ProfileError(f"{where}: {producer}.checks[{position}] has no 'id'")
    check_id = check_id.strip()

    unknown = set(entry) - {"id", "families", "cwe", "enabled", "note"}
    if unknown:
        raise ProfileError(
            f"{where}: check '{check_id}' has unknown key(s) {', '.join(sorted(unknown))}"
        )

    families = entry.get("families")
    if not isinstance(families, list) or not families:
        raise ProfileError(
            f"{where}: check '{check_id}' has no weakness-family annotation. Every check "
            f"must declare 'families' (one or more of {', '.join(sorted(_VALID_FAMILIES))}) "
            "so a detection can be attributed to a family"
        )
    named: list[str] = []
    for family in families:
        if not isinstance(family, str) or family not in _VALID_FAMILIES:
            raise ProfileError(
                f"{where}: check '{check_id}' names an unknown weakness family {family!r}; "
                f"valid values are {', '.join(sorted(_VALID_FAMILIES))}"
            )
        if family not in named:
            named.append(family)

    cwe = _string_list(entry.get("cwe"), f"check '{check_id}' cwe", where)
    for value in cwe:
        if not is_cwe_id(value):
            raise ProfileError(f"{where}: check '{check_id}' names a malformed CWE id {value!r}")

    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ProfileError(f"{where}: check '{check_id}' has a non-boolean 'enabled'")

    return Check(
        check_id=check_id,
        families=named,
        producer=producer,
        cwe=cwe,
        enabled=enabled,
        note=str(entry.get("note") or "").strip(),
    )


def _reject_duplicates(checks: Sequence[Check], where: str) -> None:
    seen: set[str] = set()
    for check in checks:
        if check.id in seen:
            raise ProfileError(
                f"{where}: check '{check.id}' is declared twice; one check has one "
                "family annotation and one CWE mapping"
            )
        seen.add(check.id)


def _string_list(raw: object, label: str, where: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ProfileError(f"{where}: {label} must be a list of strings")
    return [item.strip() for item in raw if item.strip()]
