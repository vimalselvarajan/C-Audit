"""Region hashing.

The normalization rule is that there is none. Hashes are over exact bytes:
no whitespace folding, no line-ending translation, no encoding conversion.
Two files that differ by a single tab are different evidence, because in C
they can be — a tab inside a macro continuation or a string literal changes
what the compiler sees.
"""

from __future__ import annotations

import hashlib

__all__ = ["EMPTY_SHA256", "hash_bytes", "hashes_match"]

#: sha256 of zero bytes. A legitimate value: an empty region is still a region.
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def hash_bytes(data: bytes) -> str:
    """Lowercase hex sha256 of exactly these bytes."""
    return hashlib.sha256(data).hexdigest()


def hashes_match(expected: str, observed: str) -> bool:
    """Case-insensitive comparison, so two spellings of one hash agree."""
    return expected.lower() == observed.lower()
