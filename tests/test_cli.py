"""CLI behavior: exit codes, JSON schema stability, baseline flow, report."""

import json
import textwrap

from conftest import EXAMPLE_APP
from typer.testing import CliRunner

from palisade_sec.cli import app

runner = CliRunner()

CLEAN_PROJECT = """
    def add(a, b):
        return a + b
"""

VULN_PROJECT = """
    import os
    from flask import request
    from openai import OpenAI
    client = OpenAI()

    def handler():
        q = request.json["q"]
        resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
        os.system(resp.choices[0].message.content)
"""


def _project(tmp_path, body):
    (tmp_path / "app.py").write_text(textwrap.dedent(body))
    return tmp_path


def test_scan_clean_exits_zero_friendly(tmp_path):
    proj = _project(tmp_path, CLEAN_PROJECT)
    result = runner.invoke(app, ["scan", str(proj)])
    assert result.exit_code == 0
    assert "No LLM injection paths found" in result.output


def test_scan_vuln_without_ci_still_exits_zero(tmp_path):
    proj = _project(tmp_path, VULN_PROJECT)
    result = runner.invoke(app, ["scan", str(proj)])
    assert result.exit_code == 0
    assert "PI-SHELL" in result.output


def test_scan_ci_fails_on_high(tmp_path):
    proj = _project(tmp_path, VULN_PROJECT)
    result = runner.invoke(app, ["scan", str(proj), "--ci"])
    assert result.exit_code == 1


def test_scan_ci_passes_when_baselined(tmp_path):
    proj = _project(tmp_path, VULN_PROJECT)
    assert runner.invoke(app, ["baseline", str(proj)]).exit_code == 0
    bl = proj / ".palisade" / "baseline.json"
    assert bl.is_file()
    result = runner.invoke(app, ["scan", str(proj), "--ci", "--baseline", str(bl)])
    assert result.exit_code == 0, result.output
    assert "No new findings" in result.output


def test_json_schema(tmp_path):
    proj = _project(tmp_path, VULN_PROJECT)
    result = runner.invoke(app, ["scan", str(proj), "--json"])
    assert result.exit_code == 0
    doc = json.loads(result.output)
    assert doc["schema_version"] == 1
    assert doc["summary"]["high"] == 1
    (finding,) = doc["findings"]
    assert finding["rule"] == "PI-SHELL"
    assert {"source", "llm", "sink"} <= set(finding["trace"].keys())
    assert finding["fingerprint"]
    assert finding["trace"]["source"]["snippet"]


def test_report_written(tmp_path, monkeypatch):
    proj = _project(tmp_path, VULN_PROJECT)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(proj), "--report"])
    assert result.exit_code == 0
    report = (tmp_path / "palisade-report.md").read_text()
    assert "PI-SHELL" in report
    assert "one layer of defense" in report


def test_scan_example_app_ci_fails(tmp_path):
    result = runner.invoke(app, ["scan", str(EXAMPLE_APP), "--ci"])
    assert result.exit_code == 1


def test_missing_path_exits_2():
    result = runner.invoke(app, ["scan", "/nonexistent/nowhere"])
    assert result.exit_code == 2


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "palisade-sec" in result.output
