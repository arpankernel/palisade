"""CLI behaviours a pre-launch audit reproduced against 0.5.0: gate bypasses,
tracebacks, silently ignored input, and exit codes CI cannot interpret.
Each test names the failure it pins."""

import json
import sys
import textwrap
from pathlib import Path

import pytest
from conftest import REAL_DOTENV_VALUES
from typer.testing import CliRunner

from palisade_sec import cli
from palisade_sec.cli import app
from palisade_sec.judge import config as jconfig
from palisade_sec.judge.base import FakeBackend, JudgeError

runner = CliRunner()

VULN_ROUTE = textwrap.dedent(
    """
    @app.route("/calc{n}", methods=["POST"])
    def calc{n}():
        q = request.json["q"]
        resp = client.chat.completions.create(messages=[{{"role": "user", "content": q}}])
        exec(resp.choices[0].message.content)
    """
)
HEADER = (
    "from flask import Flask, request\n"
    "from openai import OpenAI\n"
    "app = Flask(__name__)\n"
    "client = OpenAI()\n"
)


@pytest.fixture
def vuln(tmp_path):
    (tmp_path / "app.py").write_text(HEADER + VULN_ROUTE.format(n=1))
    return tmp_path


# -- baseline ---------------------------------------------------------------


def test_copy_pasted_known_vulnerability_is_new(vuln):
    """Fingerprints are line-independent, so a pasted copy of a baselined
    route shared its fingerprint and passed --ci in 0.5.0."""
    bl = vuln / "bl.json"
    assert runner.invoke(app, ["baseline", str(vuln), "--output", str(bl)]).exit_code == 0
    assert runner.invoke(app, ["scan", str(vuln), "--ci", "--baseline", str(bl)]).exit_code == 0
    src = (vuln / "app.py").read_text()
    (vuln / "app.py").write_text(src + VULN_ROUTE.format(n=1).replace("/calc1", "/calc2"))
    result = runner.invoke(app, ["scan", str(vuln), "--ci", "--baseline", str(bl)])
    assert result.exit_code == 1, result.output
    assert "new occurrence" in result.output


def test_undecodable_baseline_warns_instead_of_crashing(vuln):
    bl = vuln / "bl.json"
    bl.write_bytes(b"\xff\xfe\x00garbage")
    result = runner.invoke(app, ["scan", str(vuln), "--baseline", str(bl), "--json"])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert any("invalid baseline" in w for w in json.loads(result.stdout)["warnings"])


def test_undecodable_rule_file_warns_instead_of_crashing(vuln, tmp_path_factory):
    rules = tmp_path_factory.mktemp("rules")
    (rules / "bad.yaml").write_bytes(b"id: X\n\xff\xfe")
    result = runner.invoke(app, ["scan", str(vuln), "--rules", str(rules)])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "invalid rule file skipped" in result.output


# -- inputs and outputs -----------------------------------------------------


@pytest.mark.parametrize("flag", ["--config", "--rules"])
def test_explicit_missing_input_is_an_error(vuln, flag):
    result = runner.invoke(app, ["scan", str(vuln), flag, str(vuln / "nope")])
    assert result.exit_code == 2
    assert "not found" in result.output


def test_unwritable_output_is_a_clean_error(vuln):
    result = runner.invoke(app, ["fix", str(vuln), "--output", str(vuln)])  # a directory
    assert result.exit_code == 2, result.output
    assert "cannot write" in result.output
    assert not isinstance(result.exception, OSError)


def test_internal_error_exits_3_not_1(vuln, monkeypatch, capsys):
    """1 means "found a HIGH". A crash that also exits 1 is indistinguishable
    from a finding in CI."""

    def boom(*_a, **_k):
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(cli, "run_scan", boom)
    monkeypatch.setattr(sys, "argv", ["palisade-sec", "scan", str(vuln)])
    monkeypatch.delenv("PALISADE_DEBUG", raising=False)
    with pytest.raises(SystemExit) as exc:
        cli.run()
    assert exc.value.code == 3
    assert "bug in palisade-sec" in capsys.readouterr().err


# -- judgment layer failures --------------------------------------------------


class _Down(FakeBackend):
    def ask(self, state, questions):
        raise JudgeError("connection refused")


@pytest.fixture
def judge_down(monkeypatch):
    monkeypatch.setattr(jconfig, "get_backend", lambda: _Down(answers={}))


def test_review_survives_a_judge_outage(vuln, judge_down):
    """judged signals are advisory; an outage must not fail the deterministic gate."""
    result = runner.invoke(app, ["review", str(vuln), "--ci"])
    assert result.exit_code == 1, result.output  # the real HIGH, not a crash
    assert "judged checks skipped" in result.output
    assert not isinstance(result.exception, JudgeError)


def test_audit_reports_a_judge_outage_cleanly(vuln, judge_down):
    result = runner.invoke(app, ["audit", str(vuln)])
    assert result.exit_code == 2
    assert "judgment backend failed" in result.output


def test_audit_ci_on_nothing_scanned_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(jconfig, "get_backend", lambda: FakeBackend(answers={}))
    result = runner.invoke(app, ["audit", str(tmp_path), "--ci"])
    assert result.exit_code == 2


def test_review_baseline_warnings_are_shown(vuln):
    result = runner.invoke(
        app, ["review", str(vuln), "--ci", "--baseline", str(vuln / "nope.json")]
    )
    assert "baseline file not found" in result.output


def test_review_baseline_without_ci_is_flagged(vuln):
    result = runner.invoke(app, ["review", str(vuln), "--baseline", "x.json"])
    assert "--baseline only applies with --ci" in result.output


# -- red team -----------------------------------------------------------------


def test_redteam_variants_are_range_checked(vuln):
    assert runner.invoke(app, ["redteam", str(vuln), "--variants", "99"]).exit_code == 2


def test_redteam_flags_without_execute_are_flagged(vuln):
    result = runner.invoke(app, ["redteam", str(vuln), "--approve", "--ci"])
    assert result.exit_code == 0
    assert "only apply with --execute" in result.output


def test_redteam_target_must_be_a_url(vuln):
    result = runner.invoke(
        app, ["redteam", str(vuln), "--execute", "--approve", "--target", "not-a-url"]
    )
    assert result.exit_code == 2
    assert "http(s) URL" in result.output


def test_unreachable_target_is_not_blocked(vuln, monkeypatch):
    """0.5.0 scored "0/24 landed" and exited 0 against a closed port."""
    judge = FakeBackend(answers={})
    monkeypatch.setattr(jconfig, "get_backend", lambda: judge)
    result = runner.invoke(
        app,
        ["redteam", str(vuln), "--execute", "--approve", "--target", "http://127.0.0.1:9", "--ci"],
    )
    assert result.exit_code == 2, result.output
    assert "got no response" in result.output
    assert "blocked" not in result.stdout
    assert judge.calls == [], "no empty response may be sent to the judge"


# -- .env -----------------------------------------------------------------------


def _use_real_dotenv(monkeypatch, cwd: Path, body: str):
    (cwd / ".env").write_text(body)
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(jconfig, "_dotenv_values", REAL_DOTENV_VALUES)
    for var in (
        jconfig.BACKEND_ENV,
        jconfig.ENDPOINT_ENV,
        jconfig.MODEL_ENV,
        jconfig.TYPESAFE_KEY_ENV,
        jconfig.GENERIC_KEY_ENV,
    ):
        monkeypatch.delenv(var, raising=False)


def test_dotenv_is_read_from_the_working_directory(tmp_path, monkeypatch):
    """0.5.0 searched from the installed package, so a documented .env was
    ignored for every pip/uvx user."""
    _use_real_dotenv(monkeypatch, tmp_path, "TYPESAFE_API_KEY=from-dotenv\n")
    backend = jconfig.get_backend()
    assert backend.name == "typesafe"


def test_dotenv_endpoint_cannot_capture_a_shell_key(tmp_path, monkeypatch):
    """A cloned repo's .env must not redirect the user's real key elsewhere."""
    _use_real_dotenv(monkeypatch, tmp_path, "PALISADE_JUDGE_ENDPOINT=https://attacker.example\n")
    monkeypatch.setenv(jconfig.TYPESAFE_KEY_ENV, "real-shell-key")
    with pytest.raises(JudgeError) as exc:
        jconfig.get_backend()
    assert "refusing" in str(exc.value)
    assert "real-shell-key" not in str(exc.value)


# -- coverage honesty -----------------------------------------------------------


def test_gitignore_negation_reincludes_source(tmp_path):
    """An allowlist-style .gitignore hid everything in 0.5.0 (0 files scanned)."""
    (tmp_path / ".gitignore").write_text("*\n!src/\n!src/**\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(HEADER + VULN_ROUTE.format(n=1))
    (tmp_path / "junk.py").write_text("x = 1\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    doc = json.loads(result.stdout)
    assert doc["summary"]["files_scanned"] == 1
    assert doc["summary"]["high"] == 1


def test_js_skipped_without_extra_is_a_warning(tmp_path, monkeypatch):
    from palisade_sec import scanner
    from palisade_sec.frontends.ast_python import PythonFrontend

    monkeypatch.setattr(
        scanner,
        "_make_frontends",
        lambda: ({ext: PythonFrontend() for ext in scanner.PY_EXTENSIONS}, True),
    )
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "server.js").write_text("eval(x)\n")
    doc = json.loads(runner.invoke(app, ["scan", str(tmp_path), "--json"]).stdout)
    assert any("JS/TS file(s) skipped" in w for w in doc["warnings"])


def test_skipped_files_appear_beside_the_verdict(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "broken.py").write_text("def f(:\n")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert "1 file(s) were skipped and NOT checked" in result.output


def test_repo_config_cannot_point_rules_outside_the_repo(tmp_path, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    (tmp_path / ".palisade.toml").write_text(f'rules_dir = "{outside}"\n')
    (tmp_path / "app.py").write_text("x = 1\n")
    doc = json.loads(runner.invoke(app, ["scan", str(tmp_path), "--json"]).stdout)
    assert any("points outside the scanned tree" in w for w in doc["warnings"])


def test_sarif_records_an_empty_run_as_unsuccessful(tmp_path):
    (tmp_path / "README.md").write_text("no code\n")
    doc = json.loads(runner.invoke(app, ["scan", str(tmp_path), "--sarif"]).stdout)
    inv = doc["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    assert any(
        "nothing was scanned" in n["message"]["text"] for n in inv["toolExecutionNotifications"]
    )


def test_dotenv_naming_the_real_endpoint_still_works_with_a_shell_key(tmp_path, monkeypatch):
    """The shipped .env.example used to set the default endpoint explicitly;
    that must not trip the redirect guard, which exists for OTHER endpoints."""
    _use_real_dotenv(monkeypatch, tmp_path, "PALISADE_JUDGE_ENDPOINT=https://api.typesafe.ai\n")
    monkeypatch.setenv(jconfig.TYPESAFE_KEY_ENV, "real-shell-key")
    assert jconfig.get_backend().name == "typesafe"


def test_dotenv_endpoint_with_key_in_same_file_is_allowed(tmp_path, monkeypatch):
    _use_real_dotenv(
        monkeypatch,
        tmp_path,
        "PALISADE_JUDGE_BACKEND=openai_compatible\n"
        "PALISADE_JUDGE_ENDPOINT=http://127.0.0.1:8000/v1\n"
        "PALISADE_JUDGE_MODEL=m\n"
        "PALISADE_JUDGE_API_KEY=file-key\n",
    )
    assert jconfig.get_backend().name == "openai_compatible"
