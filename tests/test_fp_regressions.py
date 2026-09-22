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


def _run_harness(tmp_path, manifest_body: str):
    """Run the repo-corpus harness over a throwaway manifest."""
    import subprocess
    import sys

    manifest = tmp_path / "corpus.yaml"
    manifest.write_text(manifest_body)
    root = Path(__file__).parent.parent
    return subprocess.run(
        [sys.executable, str(root / "scripts" / "precision.py"), str(manifest), "--repos"],
        capture_output=True,
        text=True,
        cwd=root,
    )


_INERT = (
    "import openai\n"
    "def render(question):\n"
    "    out = openai.chat.completions.create(model='gpt-4', messages=[])\n"
    "    exec(out)\n"
)
_CHALLENGED = (
    "from flask import request\n"
    "import openai\n"
    "def handler():\n"
    "    q = request.args['q']\n"
    "    out = openai.chat.completions.create(model='gpt-4', messages=[{'role':'user'}])\n"
    "    exec(out)\n"
)


def test_unchallenged_clean_target_is_noted_not_failed(tmp_path):
    """An app-mode library with no sources is CORRECT, and must not fail.

    Library code has no `request.*`, no `input()`, no `sys.argv`, so scanned
    without `library_mode: true` there is nothing for taint to start from.
    That silence proves nothing about precision and must be excluded from the
    claim - but it is not a defect, and failing the build on it would turn
    the gate red for code behaving exactly as designed. `llm-cli` and
    `outlines` are both this case in the real corpus, so this test is what
    stops the guard breaking the weekly run.
    """
    repos = tmp_path / "repos"
    (repos / "inert").mkdir(parents=True)
    (repos / "inert" / "lib.py").write_text(_INERT)
    # A second, challenged target so the run is not wholly vacuous.
    (repos / "live").mkdir()
    (repos / "live" / "app.py").write_text(_CHALLENGED)

    proc = _run_harness(
        tmp_path,
        "threshold: 0.90\nrepos:\n"
        "  - {name: inert, url: https://example.invalid/x, kind: clean}\n"
        "  - name: live\n"
        "    url: https://example.invalid/y\n"
        "    kind: cve\n"
        "    expect:\n"
        "      - {file: app.py, line: 6, rule: PI-EXEC, verdict: flag}\n",
    )
    assert "minted no untrusted sources" in proc.stdout, proc.stdout
    assert "unchallenged  inert" in proc.stdout, proc.stdout
    assert proc.returncode == 0, (
        f"a source-free CLEAN target is correct behaviour and must not fail "
        f"the gate:\n{proc.stdout}\n{proc.stderr}"
    )


def test_target_claiming_to_be_challenged_but_minting_nothing_fails(tmp_path):
    """`kind: cve` or `library_mode` with zero sources is a real defect.

    Those targets assert a reachable vulnerability. Minting nothing means
    their ground-truth labels can never be hit, so the recall they contribute
    is unmeasurable - that fails, unlike the benign case above.
    """
    repos = tmp_path / "repos"
    (repos / "inert").mkdir(parents=True)
    (repos / "inert" / "lib.py").write_text(_INERT)

    proc = _run_harness(
        tmp_path,
        "threshold: 0.90\nrepos:\n"
        "  - name: inert\n"
        "    url: https://example.invalid/x\n"
        "    kind: cve\n"
        "    expect:\n"
        "      - {file: lib.py, line: 4, rule: PI-EXEC, verdict: flag}\n",
    )
    assert proc.returncode == 1, f"misconfigured target must fail: {proc.stdout}"
    assert "unreachable" in proc.stdout, proc.stdout


def test_guard_stays_quiet_on_a_genuinely_challenged_target(tmp_path):
    """The half that makes the guard worth having.

    Firing on a source-free target is trivially satisfied by a counter stuck
    at zero - every target would look unchallenged and the gate would go red
    for the wrong reason. So prove it also stays QUIET when sources exist.
    """
    repos = tmp_path / "repos"
    (repos / "live").mkdir(parents=True)
    (repos / "live" / "app.py").write_text(_CHALLENGED)

    proc = _run_harness(
        tmp_path,
        "threshold: 0.90\nrepos:\n"
        "  - name: live\n"
        "    url: https://example.invalid/y\n"
        "    kind: cve\n"
        "    expect:\n"
        "      - {file: app.py, line: 6, rule: PI-EXEC, verdict: flag}\n",
    )
    assert "minted no untrusted sources" not in proc.stdout, (
        "a target with a real `request.args` source must not be called "
        f"unchallenged - the counter is broken:\n{proc.stdout}"
    )


def test_source_counter_is_wired():
    """The guard is only as good as the counter behind it.

    If `sources_found` silently stopped incrementing, every target would look
    unchallenged and the gate would fail loudly - but the reverse mistake
    (counting nothing while still passing) is the dangerous one, so pin that
    real sources are actually observed.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        app = Path(d) / "app.py"
        app.write_text("from flask import request\ndef h():\n    return request.args['q']\n")
        res = run_scan(Path(d))
        assert res.sources_found > 0, "request.args is a source but none were counted"

    # And library mode must mint parameter sources where app mode does not.
    with tempfile.TemporaryDirectory() as d:
        lib = Path(d) / "lib.py"
        lib.write_text("def public(question):\n    return question\n")
        assert run_scan(Path(d)).sources_found == 0
        assert run_scan(Path(d), assume_params_untrusted=True).sources_found > 0


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
            # Every label quotes the code it points at, so a drifted clone or
            # a mistyped line number fails here instead of silently scoring.
            assert "code" in exp, f"{repo['name']}: {exp['file']}:{exp['line']} has no `code:`"
            assert exp["code"] in text, (
                f"{repo['name']}: {exp['file']}:{exp['line']} is {text.strip()!r}, "
                f"but the label says {exp['code']!r}"
            )
            checked += 1
    assert checked, "no labels were checked"
