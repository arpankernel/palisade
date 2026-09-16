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


# ---------------------------------------------------------------------------
# The precision harness must never report success without measuring anything.
# ---------------------------------------------------------------------------


def test_precision_harness_fails_on_an_unlabelled_corpus(tmp_path, monkeypatch):
    """A corpus with no `expect:` entries must FAIL, not pass vacuously.

    precision is defined as 1.0 when tp+fp is 0, so an unlabelled corpus
    otherwise sails through the gate and manufactures false confidence.
    This actually happened: the first real corpus run reported
    precision=1.000 on tp=0 fp=0 fn=0.
    """
    import subprocess
    import sys

    manifest = tmp_path / "empty.yaml"
    manifest.write_text(
        "threshold: 0.90\nrepos:\n"
        "  - {name: nothing, url: https://example.invalid/x, kind: clean}\n"
    )
    root = Path(__file__).parent.parent
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "precision.py"), str(manifest), "--repos"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    assert proc.returncode == 1, f"vacuous run must fail, got {proc.returncode}: {proc.stdout}"
    assert "no expected findings were scored" in proc.stdout


def test_corpus_labels_point_at_real_sinks():
    """Ground truth must describe the code, not the author's memory.

    A fabricated file:line would make the recall number a lie, so every
    label is checked against the cloned file when the corpus is present.
    """
    import yaml

    root = Path(__file__).parent.parent
    manifest = root / "corpus" / "repos.yaml"
    clones = root / "corpus" / "repos"
    if not clones.is_dir():
        pytest.skip("benchmark corpus not fetched (run corpus/fetch.py)")

    doc = yaml.safe_load(manifest.read_text())
    checked = 0
    for repo in doc["repos"]:
        for exp in repo.get("expect") or []:
            target = clones / repo["name"] / exp["file"]
            if not target.is_file():
                pytest.skip(f"{repo['name']} not fetched")
            lines = target.read_text(errors="replace").splitlines()
            assert 0 < exp["line"] <= len(lines), (
                f"{repo['name']}: {exp['file']}:{exp['line']} is out of range"
            )
            text = lines[exp["line"] - 1]
            assert any(k in text for k in ("exec(", "eval(", "system(", "execute(", "query(")), (
                f"{repo['name']}: {exp['file']}:{exp['line']} is not a sink: {text.strip()!r}"
            )
            checked += 1
    assert checked, "no labels were checked"
