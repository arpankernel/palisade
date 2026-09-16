"""Self-security of the scanner (SF-1/SF-2/SF-3 + resource caps).

A scanner that can be exploited by the code it scans is worse than useless.
These tests scan a deliberately hostile corpus under a `sys.addaudithook`
tripwire: any exec/eval of target code, any import of a target module, any
subprocess/os.system, and any network connection made during a scan fails
the build.
"""

import os
import shutil
import sys
from pathlib import Path

import pytest

from palisade_sec.scanner import run_scan

HOSTILE = Path(__file__).parent / "fixtures" / "hostile"
MARKERS = ["/tmp/PALISADE_HOSTILE_MARKER", "/tmp/PALISADE_HOSTILE_MARKER2"]

# One process-wide audit hook (audit hooks cannot be removed); armed per-test.
_VIOLATIONS: list[str] = []
_ARMED = {"on": False}


def _hook(event: str, args: tuple) -> None:
    if not _ARMED["on"]:
        return
    if event == "exec":
        # Only code objects originating from the scanned target are a
        # violation — the scanner importing its own modules also fires
        # 'exec' events for module code objects.
        code = args[0] if args else None
        fname = getattr(code, "co_filename", "")
        if "fixtures/hostile" in fname.replace(os.sep, "/") or fname == "<string>":
            _VIOLATIONS.append(f"exec of target code: {fname}")
    elif event in ("system", "os.system", "subprocess.Popen", "os.exec", "socket.connect"):
        _VIOLATIONS.append(f"{event}: {args!r:.120}")
    elif event == "import":
        name = str(args[0]) if args else ""
        if any(k in name for k in ("evil_sideeffect", "hostile", "longline", "deep_")):
            _VIOLATIONS.append(f"import of target module: {name}")
    elif event == "compile":
        # ast.parse fires 'compile' with PyCF_ONLY_AST — allowed. An actual
        # compile-to-bytecode of target source would surface via 'exec'.
        pass


sys.addaudithook(_hook)


@pytest.fixture()
def tripwire():
    for m in MARKERS:
        if os.path.exists(m):
            os.remove(m)
    _VIOLATIONS.clear()
    _ARMED["on"] = True
    try:
        yield _VIOLATIONS
    finally:
        _ARMED["on"] = False
        for m in MARKERS:
            if os.path.exists(m):
                os.remove(m)


def test_hostile_corpus_never_executes_and_never_crashes(tripwire):
    """SF-1 + RB-3: the whole hostile corpus scans without executing target
    code, without network, and without crashing the run."""
    res = run_scan(HOSTILE)
    assert not tripwire, f"scanner triggered forbidden operations: {tripwire}"
    for m in MARKERS:
        assert not os.path.exists(m), "scanned code was executed (marker written)"
    # malformed files are skipped with a warning, never fatal
    skipped = " ".join(res.skipped)
    for name in ("broken.py", "deep_parens.py", "nullbyte.py", "huge.py"):
        assert name in skipped, f"{name} should be skipped with a warning: {res.skipped}"
    # and the genuinely vulnerable file in the corpus is still analyzed
    assert any(f.rule_id == "PI-SHELL" for f in res.findings)


def test_scan_makes_no_network_calls(tripwire):
    """SF-2: a normal scan opens no sockets."""
    run_scan(Path(__file__).parent.parent / "examples" / "vulnerable-app")
    net = [v for v in tripwire if "socket" in v]
    assert not net, f"scan attempted network access: {net}"


def test_symlink_escape_not_followed(tmp_path):
    """SF-3: a symlink inside the tree pointing outside the scan root is
    skipped, not read."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret_vuln.py"
    secret.write_text(
        "import os\nfrom flask import request\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def h():\n"
        "    q = request.json['q']\n"
        "    r = client.chat.completions.create(messages=[{'role': 'user', 'content': q}])\n"
        "    os.system(r.choices[0].message.content)\n"
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "ok.py").write_text("x = 1\n")
    os.symlink(secret, project / "sneaky.py")
    res = run_scan(project)
    assert res.findings == []
    assert any("escapes the scan root" in s for s in res.skipped)


def test_max_file_bytes_configurable(tmp_path):
    (tmp_path / "big.py").write_text("x = 1\n" * 200)
    (tmp_path / ".palisade.toml").write_text("max_file_bytes = 100\n")
    res = run_scan(tmp_path)
    assert res.files_scanned == 0
    assert any("max_file_bytes" in s for s in res.skipped)


def test_snippet_redaction_caps_long_lines():
    """Findings on pathological lines never carry the whole line (secrets)."""
    res = run_scan(HOSTILE)
    hits = [f for f in res.findings if f.source.file.endswith("longline.py")]
    assert hits, "longline.py vulnerability should still be found"
    for f in hits:
        for tp in (f.source, f.llm, f.sink):
            assert len(tp.snippet) <= 201
    assert "A" * 250 not in hits[0].source.snippet


def test_scan_time_budget(tmp_path):
    for i in range(30):
        (tmp_path / f"m{i}.py").write_text("x = 1\n")
    (tmp_path / ".palisade.toml").write_text("max_scan_seconds = 0.0\n")
    res = run_scan(tmp_path)
    assert res.files_scanned == 0
    assert any("time budget" in w for w in res.warnings)


def test_hostile_corpus_is_deterministic():
    """Same input, same output — ordering never depends on filesystem order."""
    a = run_scan(HOSTILE)
    b = run_scan(HOSTILE)
    key = lambda r: [(f.rule_id, f.file, f.line, f.fingerprint) for f in r.findings]  # noqa: E731
    assert key(a) == key(b)
    assert sorted(a.skipped) == sorted(b.skipped)


@pytest.mark.skipif(shutil.which("true") is None, reason="POSIX only")
def test_no_subprocess_during_scan(tripwire):
    run_scan(HOSTILE)
    procs = [v for v in tripwire if "Popen" in v or "system" in v]
    assert not procs, f"scan spawned processes: {procs}"
