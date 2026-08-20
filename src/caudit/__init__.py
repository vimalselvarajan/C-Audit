"""C Audit — compiler-aware, evidence-gated auditing for C and C++.

Guiding principle from the specification: use AI to connect and explain
evidence, not to invent it.
"""

from importlib import metadata

__all__ = ["__version__"]


def _package_version() -> str:
    try:
        return metadata.version("caudit")
    except metadata.PackageNotFoundError:  # pragma: no cover - source checkout only
        return "0.0.0+unknown"


__version__ = _package_version()
