"""Deterministic, checksummed public evidence bundles."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from caudit import __version__
from caudit.errors import UsageError

__all__ = [
    "BundleArtifact",
    "BundleManifest",
    "build_reproducible_bundle",
    "verify_reproducible_bundle",
]

_SAFE_SUFFIXES = frozenset({".json", ".jsonl", ".md", ".csv", ".yaml", ".yml", ".txt"})
_FORBIDDEN_PARTS = frozenset(
    {
        ".env",
        "llm-cache",
        "prompts",
        "workspace",
        "compile-commands",
        "adjudication-checkpoints",
        "__pycache__",
    }
)


class BundleArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    sha256: str = Field(min_length=64, max_length=64)
    size: int = Field(ge=0)


class BundleManifest(BaseModel):
    """Content identity only: no clock, host path, uid, or mutable metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    generator: str = f"caudit {__version__}"
    artifacts: list[BundleArtifact]
    tables_sha256: str = Field(min_length=64, max_length=64)


def build_reproducible_bundle(
    *,
    root: Path,
    inputs: list[Path],
    output: Path,
) -> tuple[Path, BundleManifest]:
    """Write a byte-identical tar for identical public artifacts."""

    base = root.resolve()
    files = _collect(base, inputs)
    payloads = {relative: path.read_bytes() for relative, path in files.items()}
    tables = _tables(payloads)
    table_bytes = _json_bytes(tables)
    artifacts = [
        BundleArtifact(path=str(relative), sha256=_sha(data), size=len(data))
        for relative, data in payloads.items()
    ]
    manifest = BundleManifest(
        artifacts=artifacts,
        tables_sha256=_sha(table_bytes),
    )
    manifest_bytes = _json_bytes(json.loads(manifest.model_dump_json()))

    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        _add_bytes(archive, "bundle-manifest.json", manifest_bytes)
        _add_bytes(archive, "regenerated-tables.json", table_bytes)
        for relative, data in payloads.items():
            _add_bytes(archive, f"artifacts/{relative}", data)
    return output, manifest


def verify_reproducible_bundle(path: Path) -> BundleManifest:
    """Refuse path traversal, duplicates, missing files, and checksum drift."""

    try:
        with tarfile.open(path, mode="r") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise UsageError("bundle contains duplicate paths")
            if any(_unsafe_tar_name(name) for name in names):
                raise UsageError("bundle contains an unsafe path")
            extracted: dict[str, bytes] = {}
            for member in members:
                if not member.isfile():
                    continue
                stream = archive.extractfile(member)
                if stream is not None:
                    extracted[member.name] = stream.read()
    except (OSError, tarfile.TarError) as exc:
        raise UsageError(f"cannot read evidence bundle {path}: {exc}") from exc

    try:
        manifest = BundleManifest.model_validate_json(extracted["bundle-manifest.json"])
        tables = extracted["regenerated-tables.json"]
    except (KeyError, ValueError) as exc:
        raise UsageError(f"bundle manifest is missing or invalid: {exc}") from exc
    if _sha(tables) != manifest.tables_sha256:
        raise UsageError("regenerated table checksum does not match the manifest")
    expected = {f"artifacts/{artifact.path}": artifact for artifact in manifest.artifacts}
    actual = {name for name in extracted if name.startswith("artifacts/")}
    if actual != set(expected):
        raise UsageError("bundle artifact inventory does not match the manifest")
    for name, artifact in expected.items():
        data = extracted[name]
        if len(data) != artifact.size or _sha(data) != artifact.sha256:
            raise UsageError(f"bundle artifact checksum does not match: {artifact.path}")
    return manifest


def _collect(base: Path, inputs: list[Path]) -> dict[PurePosixPath, Path]:
    collected: dict[PurePosixPath, Path] = {}
    for supplied in inputs:
        resolved = (base / supplied).resolve() if not supplied.is_absolute() else supplied.resolve()
        if resolved != base and base not in resolved.parents:
            raise UsageError(f"bundle input is outside the declared root: {supplied}")
        candidates = [resolved] if resolved.is_file() else sorted(resolved.rglob("*"))
        for path in candidates:
            if not path.is_file():
                continue
            relative = PurePosixPath(path.relative_to(base).as_posix())
            if any(part in _FORBIDDEN_PARTS for part in relative.parts):
                continue
            if path.suffix.lower() not in _SAFE_SUFFIXES:
                continue
            collected[relative] = path
    if not collected:
        raise UsageError("no public JSON/JSONL/Markdown/CSV/YAML/text artifacts were selected")
    return dict(sorted(collected.items(), key=lambda item: str(item[0])))


def _tables(payloads: dict[PurePosixPath, bytes]) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    matrices: list[dict[str, object]] = []
    for path, data in payloads.items():
        if path.suffix != ".json":
            continue
        try:
            payload = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("metrics"), dict):
            metrics = payload["metrics"]
            experiment = payload.get("experiment") or {}
            runs.append(
                {
                    "path": str(path),
                    "suite": metrics.get("suite"),
                    "condition": experiment.get("condition"),
                    "precision": metrics.get("precision"),
                    "recall": metrics.get("recall"),
                    "macro_f2": metrics.get("macro_f2"),
                    "confirmed_count": metrics.get("confirmed_count"),
                    "review_required_count": metrics.get("review_required_count"),
                }
            )
        if isinstance(payload, dict) and "rows" in payload and "invariant" in payload:
            matrices.append(
                {
                    "path": str(path),
                    "suite": payload.get("suite"),
                    "rows": payload.get("rows"),
                }
            )
    return {"schema_version": "1", "runs": runs, "attribution_matrices": matrices}


def _add_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info, io.BytesIO(data))


def _unsafe_tar_name(name: str) -> bool:
    path = PurePosixPath(name)
    return path.is_absolute() or ".." in path.parts or str(path) != name


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
