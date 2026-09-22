"""What a user gets from a plain install, not from this dev environment.

The dev environment has every optional extra installed, so the whole suite
passed while a default `uvx palisade-sec review .` crashed with an httpx
ImportError traceback, and a JS-only repo without the `[js]` extra printed a
green tick over zero scanned files and passed `--ci`. Both shipped in 0.5.0.
These tests simulate the missing pieces directly so neither can come back.
"""

import json
import sys
import textwrap
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from palisade_sec.cli import app

runner = CliRunner()

ROOT = Path(__file__).parent.parent

VULN = textwrap.dedent(
    """
    import os
    from flask import request
    from openai import OpenAI
    client = OpenAI()

    def handler():
        q = request.json["q"]
        resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
        os.system(resp.choices[0].message.content)
    """
)

# Every module that imports httpx at import time. Evicting them forces the
# judge adapters to re-import, which then fails exactly as it does on a
# default install where the `[judge]` extra is absent.
_HTTPX_USERS = (
    "palisade_sec.judge.typesafe",
    "palisade_sec.judge.openai_compatible",
    "palisade_sec.judge._http",
)


@pytest.fixture
def no_judge_extra(monkeypatch):
    """Make `import httpx` fail, as on `pip install palisade-sec`."""
    monkeypatch.setitem(sys.modules, "httpx", None)
    for mod in _HTTPX_USERS:
        monkeypatch.delitem(sys.modules, mod, raising=False)
    # A key must not matter: the extra is checked before it would be used.
    monkeypatch.setenv("TYPESAFE_API_KEY", "dummy-not-a-real-key")
    monkeypatch.delenv("PALISADE_JUDGE_BACKEND", raising=False)


@pytest.fixture
def vuln_project(tmp_path):
    (tmp_path / "app.py").write_text(VULN)
    return tmp_path


# ---------------------------------------------------------------------------
# 1. Judgment layer without the `[judge]` extra
# ---------------------------------------------------------------------------


def test_review_degrades_to_taint_only_without_the_extra(no_judge_extra, vuln_project):
    result = runner.invoke(app, ["review", str(vuln_project)])
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output
    assert result.exit_code == 0, result.output
    # The findings still come through, and the user is told how to get more.
    assert "PI-SHELL" in result.output
    assert "palisade-sec[judge]" in result.stderr


def test_review_json_stays_parseable_without_the_extra(no_judge_extra, vuln_project):
    result = runner.invoke(app, ["review", str(vuln_project), "--json"])
    assert result.exit_code == 0, result.output
    json.loads(result.stdout)  # the explanatory note must go to stderr only


def test_audit_explains_the_missing_extra(no_judge_extra, vuln_project):
    result = runner.invoke(app, ["audit", str(vuln_project)])
    assert result.exit_code == 2
    assert not isinstance(result.exception, ImportError), result.exception
    assert "palisade-sec[judge]" in result.output


def test_redteam_execute_explains_the_missing_extra(no_judge_extra, vuln_project):
    result = runner.invoke(
        app,
        ["redteam", str(vuln_project), "--execute", "--approve", "--target", "http://127.0.0.1:9"],
    )
    assert result.exit_code == 2
    assert not isinstance(result.exception, ImportError), result.exception
    assert "palisade-sec[judge]" in result.output


def test_missing_extra_message_names_no_secret(no_judge_extra):
    """The error text must never echo the key it didn't get to use."""
    from palisade_sec.judge.base import JudgeError
    from palisade_sec.judge.config import get_backend

    with pytest.raises(JudgeError) as exc:
        get_backend()
    assert "dummy-not-a-real-key" not in str(exc.value)


# ---------------------------------------------------------------------------
# 2. A scan that read nothing must never look like a pass
# ---------------------------------------------------------------------------


@pytest.fixture
def nothing_to_scan(tmp_path):
    (tmp_path / "README.md").write_text("no source code here\n")
    return tmp_path


def test_empty_scan_prints_no_green_tick(nothing_to_scan):
    result = runner.invoke(app, ["scan", str(nothing_to_scan)])
    assert result.exit_code == 0
    assert "✓" not in result.output
    assert "Nothing was scanned" in result.output


def test_empty_scan_fails_ci(nothing_to_scan):
    result = runner.invoke(app, ["scan", str(nothing_to_scan), "--ci"])
    assert result.exit_code == 2, result.output
    assert "checked nothing" in result.output


def test_empty_scan_is_flagged_in_json(nothing_to_scan):
    result = runner.invoke(app, ["scan", str(nothing_to_scan), "--json"])
    doc = json.loads(result.stdout)
    assert doc["summary"]["files_scanned"] == 0
    assert any("nothing was scanned" in w for w in doc["warnings"])


def test_empty_review_fails_ci(nothing_to_scan, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    result = runner.invoke(app, ["review", str(nothing_to_scan), "--ci"])
    assert result.exit_code == 2, result.output


def test_empty_fix_writes_no_plan(nothing_to_scan, monkeypatch):
    monkeypatch.chdir(nothing_to_scan)
    result = runner.invoke(app, ["fix", "."])
    assert "✓" not in result.output
    assert not (nothing_to_scan / "palisade-fixes.md").exists()


def test_empty_markdown_report_does_not_claim_clean():
    from palisade_sec.report import to_markdown

    md = to_markdown([], 0, "x")
    assert "No LLM injection paths found" not in md
    assert "Nothing was scanned" in md


def test_a_real_clean_scan_still_gets_its_tick(tmp_path):
    """The guard must not swallow the genuinely clean case."""
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci"])
    assert result.exit_code == 0
    assert "✓ No LLM injection paths found" in result.output


# ---------------------------------------------------------------------------
# 3. Rules must not cite CVEs our own corpus rules out of contract
# ---------------------------------------------------------------------------


def test_rules_do_not_cite_out_of_contract_cves():
    """A CVE the benchmark scores `clean` (no LLM on the path, so not a prompt
    injection) must not be shown to users as evidence for a rule. 0.5.0 printed
    Langflow's CVE-2025-3248 under every PI-EXEC finding while the corpus, the
    proof-scans page and the website all said Palisade does not cover it."""
    corpus = yaml.safe_load((ROOT / "corpus" / "repos.yaml").read_text())
    out_of_contract = {
        r["cve"] for r in corpus["repos"] if r.get("cve") and r.get("kind", "clean") == "clean"
    }
    assert out_of_contract, "expected at least one out-of-contract CVE to guard (Langflow)"

    rules_dir = ROOT / "src" / "palisade_sec" / "rules"
    for rule_file in sorted(rules_dir.glob("*.yaml")):
        text = rule_file.read_text()
        for cve in out_of_contract:
            assert cve not in text, f"{rule_file.name} cites {cve}, which the corpus scores clean"
