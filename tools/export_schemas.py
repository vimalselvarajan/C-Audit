#!/usr/bin/env python3
"""Write or verify the committed JSON Schemas.

``python tools/export_schemas.py`` rewrites ``schemas/``;
``python tools/export_schemas.py --check`` fails if anything drifted. CI runs
the second form, so a model change without a schema export cannot merge.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caudit.application.schema_export import check_drift, write_all


def main(argv: list[str]) -> int:
    if "--check" in argv:
        drifted = check_drift()
        if not drifted:
            print("schemas up to date")
            return 0
        for drift in drifted:
            print(f"error: {drift.message()}", file=sys.stderr)
        return 1
    for path in write_all():
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
