"""False-positive regression corpus.

Every file in tests/fixtures/regressions/ is code Palisade must stay silent
on. These are the highest-value tests in the repo: a security tool that
cries wolf gets uninstalled, and precision must only ever ratchet upward.

Adding a reported false positive here makes it permanently impossible to
reintroduce. See that directory's README for the process.
"""

from pathlib import Path

import pytest

from palisade_sec.scanner import run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "regressions"
CASES = sorted(p for p in FIXTURES.glob("*.*") if p.suffix in {".py", ".js", ".ts"})


def test_the_corpus_is_not_empty():
    """Guard against the discovery glob silently matching nothing."""
    assert CASES, "no regression fixtures found - the harness would pass vacuously"


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.stem)
def test_must_stay_silent(case, tmp_path):
    # Scan each case in isolation so one fixture cannot mask another.
    target = tmp_path / case.name
    target.write_text(case.read_text())
    res = run_scan(tmp_path)
    assert res.skipped == [], f"fixture failed to parse: {res.skipped}"
    assert res.findings == [], (
        f"{case.name} is a known false-positive case and must stay silent, "
        f"but produced: {[(f.rule_id, f.line) for f in res.findings]}"
    )
