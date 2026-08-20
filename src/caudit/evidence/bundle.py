"""The closed world a model is allowed to cite.

Everything a model sees passes through a bundle, and a bundle captures the
bytes of each region at the moment it is added. That capture is what makes
part 09's compression reversible: a summary can carry a handle, and
``zoom`` returns the original bytes rather than re-reading a file that may
since have changed.
"""

from __future__ import annotations

from collections.abc import Iterator

from caudit.evidence.hashing import hash_bytes, hashes_match
from caudit.evidence.store import SourceStore
from caudit.model.evidence import EvidenceItem, EvidenceKind, Provenance
from caudit.model.source import SourceRegion, Symbol

__all__ = ["EvidenceBundle"]


class EvidenceBundle:
    """A set of evidence items plus the exact bytes each one quotes."""

    def __init__(self, store: SourceStore) -> None:
        self._store = store
        self._items: dict[str, EvidenceItem] = {}
        self._originals: dict[str, bytes] = {}

    # ------------------------------------------------------------------ add

    def add(self, item: EvidenceItem) -> str:
        """Add an item and capture its bytes. Returns the evidence id.

        Re-adding an identical item is a no-op; adding a *different* item
        under the same content address is impossible by construction, since
        the address covers the content.
        """
        if item.evidence_id not in self._items:
            self._items[item.evidence_id] = item
            self._originals[item.evidence_id] = self._store.read_region(item.region)
        return item.evidence_id

    def add_region(
        self,
        region: SourceRegion,
        kind: EvidenceKind,
        provenance: list[Provenance],
        symbol: Symbol | None = None,
    ) -> str:
        """Convenience: build the item from its region and add it."""
        return self.add(
            EvidenceItem.create(kind=kind, region=region, provenance=provenance, symbol=symbol)
        )

    # ------------------------------------------------------------------ read

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def zoom(self, evidence_id: str) -> bytes:
        """The exact original bytes of a cited region.

        Raises ``KeyError`` for an id the bundle never issued — an invented
        handle cannot be turned into source.
        """
        return self._originals[evidence_id]

    def verify(self, evidence_id: str) -> bool:
        """Whether the captured bytes still hash to the recorded value."""
        item = self._items.get(evidence_id)
        if item is None:
            return False
        return hashes_match(item.region.sha256, hash_bytes(self._originals[evidence_id]))

    def ids(self) -> tuple[str, ...]:
        """Every issued id, in insertion order."""
        return tuple(self._items)

    def __contains__(self, evidence_id: object) -> bool:
        return isinstance(evidence_id, str) and evidence_id in self._items

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[EvidenceItem]:
        return iter(self._items.values())
