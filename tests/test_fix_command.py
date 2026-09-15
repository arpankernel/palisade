"""`palisade-sec fix`: deterministic remediation plans."""

import textwrap

from conftest import EXAMPLE_APP
from typer.testing import CliRunner

from palisade_sec.cli import app

runner = CliRunner()


def test_fix_writes_plan_for_example_app(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["fix", str(EXAMPLE_APP), "--all"])
    assert result.exit_code == 0, result.output
    plan = (tmp_path / "palisade-fixes.md").read_text()
    # one tailored guardrail per rule family present in the example app
    assert "validate_generated_code" in plan  # PI-EXEC
    assert "run_model_command" in plan  # PI-SHELL
    assert "validate_generated_sql" in plan  # PI-SQL
    # every guardrail ships with its regression test
    assert plan.count("```python") >= 10
    assert "test_guardrail_blocks_injected_code" in plan
    # the partial-defense finding calls out that the denylist is insufficient
    assert "not sufficient" in plan


def test_fix_clean_project_writes_nothing(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        textwrap.dedent(
            """
            def add(a, b):
                return a + b
            """
        )
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["fix", str(tmp_path)])
    assert result.exit_code == 0
    assert "No findings to fix" in result.output
    assert not (tmp_path / "palisade-fixes.md").exists()


def test_fix_never_modifies_scanned_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = {p: p.read_bytes() for p in EXAMPLE_APP.rglob("*.py")}
    runner.invoke(app, ["fix", str(EXAMPLE_APP)])
    after = {p: p.read_bytes() for p in EXAMPLE_APP.rglob("*.py")}
    assert before == after
