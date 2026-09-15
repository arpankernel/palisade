"""Baseline behavior: deterministic file, new-vs-known diff, line-shift
resilience (BL-1..BL-4)."""

import json
import textwrap
from pathlib import Path

from palisade_sec.baseline import diff_against_baseline, write_baseline
from palisade_sec.scanner import run_scan

VULN = """
    import os
    from flask import request
    from openai import OpenAI
    client = OpenAI()

    def handler():
        q = request.json["q"]
        resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
        os.system(resp.choices[0].message.content)
"""

SECOND_VULN = """
    def handler2():
        q2 = request.json["q2"]
        resp2 = client.chat.completions.create(messages=[{"role": "user", "content": q2}])
        exec(resp2.choices[0].message.content)
"""


def _write(tmp_path: Path, extra: str = "", prefix_lines: int = 0) -> Path:
    body = textwrap.dedent(VULN) + textwrap.dedent(extra)
    if prefix_lines:
        header = "# padding\n" * prefix_lines
        body = body.replace("import os", "import os\n" + header, 1)
    (tmp_path / "app.py").write_text(body)
    return tmp_path


def test_baseline_roundtrip_all_known(tmp_path):
    _write(tmp_path)
    res = run_scan(tmp_path)
    assert len(res.findings) == 1
    bl = tmp_path / ".palisade" / "baseline.json"
    write_baseline(res.findings, bl)

    diff = diff_against_baseline(run_scan(tmp_path).findings, bl)
    assert diff.new == []
    assert len(diff.known) == 1
    assert diff.stale == []


def test_baseline_only_new_finding_fails(tmp_path):
    _write(tmp_path)
    bl = tmp_path / ".palisade" / "baseline.json"
    write_baseline(run_scan(tmp_path).findings, bl)

    _write(tmp_path, extra=SECOND_VULN)
    diff = diff_against_baseline(run_scan(tmp_path).findings, bl)
    assert len(diff.known) == 1
    assert len(diff.new) == 1
    assert diff.new[0].rule_id == "PI-EXEC"


def test_fingerprint_survives_line_shift(tmp_path):
    """BL-1: fingerprints are code-based, not line-based."""
    _write(tmp_path)
    bl = tmp_path / ".palisade" / "baseline.json"
    write_baseline(run_scan(tmp_path).findings, bl)

    _write(tmp_path, prefix_lines=7)  # shift everything down 7 lines
    diff = diff_against_baseline(run_scan(tmp_path).findings, bl)
    assert diff.new == [], "a pure line shift must not create new findings"
    assert len(diff.known) == 1


def test_baseline_file_deterministic_and_sorted(tmp_path):
    _write(tmp_path, extra=SECOND_VULN)
    res = run_scan(tmp_path)
    b1 = tmp_path / "b1.json"
    b2 = tmp_path / "b2.json"
    write_baseline(res.findings, b1)
    write_baseline(list(reversed(res.findings)), b2)
    assert b1.read_text() == b2.read_text()
    doc = json.loads(b1.read_text())
    assert list(doc["findings"].keys()) == sorted(doc["findings"].keys())


def test_stale_entries_reported(tmp_path):
    _write(tmp_path, extra=SECOND_VULN)
    bl = tmp_path / ".palisade" / "baseline.json"
    write_baseline(run_scan(tmp_path).findings, bl)

    _write(tmp_path)  # second vuln removed
    diff = diff_against_baseline(run_scan(tmp_path).findings, bl)
    assert len(diff.stale) == 1


def test_invalid_baseline_ignored_not_crash(tmp_path):
    _write(tmp_path)
    bl = tmp_path / "corrupt.json"
    bl.write_text("{not json")
    diff = diff_against_baseline(run_scan(tmp_path).findings, bl)
    assert diff.warnings
    assert len(diff.new) == 1  # everything treated as new
