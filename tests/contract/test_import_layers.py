from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_import_layer_contracts_hold() -> None:
    repository = Path(__file__).resolve().parents[2]

    completed = subprocess.run(
        [sys.executable, "-m", "importlinter.cli"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
