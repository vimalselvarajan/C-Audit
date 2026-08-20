"""Part 08 golden test: T-08-05 (AC-08-5).

The snapshot is small on purpose, and re-recording it is deliberately not
free: the counts it contains are asserted independently in
``tests/unit/test_report_markdown.py``, so a blind ``--record`` after an
accidental change to the promotion policy breaks a second test rather than
quietly baking the new behaviour into the committed file.

Regenerate with::

    python -m tests.golden.test_report_markdown --record
"""

from __future__ import annotations

import sys
from pathlib import Path

from caudit.report.markdown import render_markdown
from tests.conftest import demo_manifest, demo_sections, write_demo_repo

GOLDEN = Path(__file__).parent / "report" / "report.md"


def _render(root: Path) -> str:
    sections = demo_sections(root)
    return render_markdown(sections, demo_manifest(root, sections))


def test_the_six_finding_report_matches_the_committed_snapshot(tmp_path: Path) -> None:
    """T-08-05: byte-for-byte, so an unintended rendering change is visible."""
    rendered = _render(write_demo_repo(tmp_path / "demo"))
    committed = GOLDEN.read_text(encoding="utf-8")
    assert rendered == committed, (
        "report.md no longer matches the committed snapshot. If the change is "
        "intended, re-record it and update the count assertions in "
        "tests/unit/test_report_markdown.py in the same change."
    )


def test_the_snapshot_carries_no_machine_specific_value() -> None:
    """A golden file that embedded a tmp path would pass on one machine only."""
    committed = GOLDEN.read_text(encoding="utf-8")
    assert "/tmp/" not in committed
    assert not any(line.startswith("/") for line in committed.splitlines())


def _record() -> None:  # pragma: no cover - developer tool
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(_render(write_demo_repo(Path(scratch) / "demo")), encoding="utf-8")
    print(f"recorded {GOLDEN}")


if __name__ == "__main__":  # pragma: no cover - developer tool
    if "--record" in sys.argv:
        _record()
    else:
        print(__doc__)
