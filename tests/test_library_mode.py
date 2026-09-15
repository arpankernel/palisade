"""Library mode (--assume-params-untrusted): parameters of public functions
become untrusted sources. Off by default. Every must-flag case has a
must-not-flag twin — precision rules."""

import textwrap

from typer.testing import CliRunner

from palisade_sec.cli import app
from palisade_sec.scanner import run_scan

runner = CliRunner()

LIB_VULN = """
    from openai import OpenAI
    client = OpenAI()

    def answer(question):
        resp = client.chat.completions.create(
            messages=[{"role": "user", "content": question}]
        )
        exec(resp.choices[0].message.content)
"""


def _project(tmp_path, body):
    (tmp_path / "lib.py").write_text(textwrap.dedent(body))
    return tmp_path


def test_public_param_to_llm_to_exec_flagged(tmp_path):
    proj = _project(tmp_path, LIB_VULN)
    res = run_scan(proj, assume_params_untrusted=True)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "PI-EXEC"
    assert f.severity == "high"
    assert f.source.detail == "param:question"


def test_off_by_default(tmp_path):
    """The same library is silent without the flag (and without config)."""
    proj = _project(tmp_path, LIB_VULN)
    assert run_scan(proj).findings == []
    assert run_scan(proj, assume_params_untrusted=False).findings == []


def test_private_function_params_not_tainted(tmp_path):
    proj = _project(tmp_path, LIB_VULN.replace("def answer(", "def _answer("))
    assert run_scan(proj, assume_params_untrusted=True).findings == []


def test_unused_param_constant_prompt_silent(tmp_path):
    """A public function with a param is not enough — the param must actually
    reach the LLM."""
    proj = _project(
        tmp_path,
        """
        from openai import OpenAI
        client = OpenAI()

        def cron(unused_config):
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": "print the date"}]
            )
            exec(resp.choices[0].message.content)
        """,
    )
    assert run_scan(proj, assume_params_untrusted=True).findings == []


def test_param_to_sink_without_llm_silent(tmp_path):
    """param -> exec with no LLM hop stays out of contract even in library
    mode (that's Bandit's finding, not ours)."""
    proj = _project(
        tmp_path,
        """
        def run_snippet(code):
            exec(code)
        """,
    )
    assert run_scan(proj, assume_params_untrusted=True).findings == []


def test_cli_flag_wiring(tmp_path):
    proj = _project(tmp_path, LIB_VULN)
    off = runner.invoke(app, ["scan", str(proj), "--ci"])
    assert off.exit_code == 0
    on = runner.invoke(app, ["scan", str(proj), "--ci", "--assume-params-untrusted"])
    assert on.exit_code == 1
    assert "param:question" not in off.output


def test_config_file_can_enable(tmp_path):
    proj = _project(tmp_path, LIB_VULN)
    (proj / ".palisade.toml").write_text("assume_params_untrusted = true\n")
    assert len(run_scan(proj).findings) == 1
    # explicit False from the caller overrides config
    assert run_scan(proj, assume_params_untrusted=False).findings == []
