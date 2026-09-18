"""Resilience contract: a scan either produces a trustworthy verdict or says
it could not.

Two failure modes are covered, both of which previously degraded silently:

  RB-3  one pathological file must not abort the whole scan - the other
        files' findings are still reported, the bad file is listed in
        `skipped`.
  RB-5  an internal error must exit 3, never 1. A CI gate reads exit 1 as
        "a HIGH finding exists"; a crash reporting 1 is a false alarm, and a
        crash reporting 0 would be a silently failed gate.
"""

import io
import json
import textwrap

import pytest
from typer.testing import CliRunner

from palisade_sec.cli import EXIT_FINDINGS, EXIT_INTERNAL, EXIT_USAGE, app

runner = CliRunner()

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

CLEAN = """
    def add(a, b):
        return a + b
"""


# --------------------------------------------------------------------------
# RB-3: per-file crash isolation
# --------------------------------------------------------------------------


def test_one_broken_file_does_not_lose_other_findings(tmp_path, monkeypatch):
    """A lowering bug on one file must not hide the vulnerability in another."""
    proj = tmp_path
    (proj / "vuln.py").write_text(textwrap.dedent(VULN))
    (proj / "other.py").write_text(textwrap.dedent(CLEAN))

    from palisade_sec.frontends import ast_python

    original = ast_python._Lowerer.lower_module

    def explode(self, tree):
        if self.rel_path.endswith("other.py"):
            raise AttributeError("simulated lowering bug")
        return original(self, tree)

    monkeypatch.setattr(ast_python._Lowerer, "lower_module", explode)

    result = runner.invoke(app, ["scan", str(proj), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    # the vulnerability in the OTHER file is still reported
    assert payload["summary"]["high"] == 1, payload
    # and the broken file is accounted for, not silently dropped
    assert any("other.py" in s and "internal error" in s for s in payload["skipped"]), payload


def test_broken_file_is_reported_as_skipped_not_scanned(tmp_path, monkeypatch):
    """A file that failed to lower must not be counted as scanned."""
    proj = tmp_path
    (proj / "a.py").write_text(textwrap.dedent(CLEAN))
    (proj / "b.py").write_text(textwrap.dedent(CLEAN))

    from palisade_sec.frontends import ast_python

    original = ast_python._Lowerer.lower_module

    def explode(self, tree):
        if self.rel_path.endswith("b.py"):
            raise RuntimeError("boom")
        return original(self, tree)

    monkeypatch.setattr(ast_python._Lowerer, "lower_module", explode)

    result = runner.invoke(app, ["scan", str(proj), "--json"])
    payload = json.loads(result.output)
    assert payload["summary"]["files_scanned"] == 1
    assert len(payload["skipped"]) == 1


# --------------------------------------------------------------------------
# RB-5: the crash boundary and the exit-code contract
# --------------------------------------------------------------------------


def test_internal_error_exits_three_not_one(tmp_path, monkeypatch):
    """Exit 1 means "HIGH finding". A crash must not impersonate one."""
    proj = tmp_path
    (proj / "app.py").write_text(textwrap.dedent(CLEAN))

    import palisade_sec.cli as cli

    def explode(*args, **kwargs):
        raise RuntimeError("simulated internal bug")

    monkeypatch.setattr(cli, "run_scan", explode)

    result = runner.invoke(app, ["scan", str(proj), "--ci"])
    assert result.exit_code == EXIT_INTERNAL
    assert result.exit_code != EXIT_FINDINGS
    assert "internal error" in result.output


def test_internal_error_exit_code_is_distinct_from_all_others():
    """The four documented codes must stay mutually distinct."""
    from palisade_sec.cli import EXIT_OK

    assert len({EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_INTERNAL}) == 4


def test_keyboard_interrupt_exits_three(tmp_path, monkeypatch):
    """An interrupted scan proved nothing; it must not report success."""
    proj = tmp_path
    (proj / "app.py").write_text(textwrap.dedent(CLEAN))

    import palisade_sec.cli as cli

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_scan", interrupt)

    result = runner.invoke(app, ["scan", str(proj)])
    assert result.exit_code == EXIT_INTERNAL


def test_crash_boundary_does_not_swallow_real_findings(tmp_path):
    """The boundary must not change the verdict on a healthy scan."""
    proj = tmp_path
    (proj / "app.py").write_text(textwrap.dedent(VULN))
    result = runner.invoke(app, ["scan", str(proj), "--ci"])
    assert result.exit_code == EXIT_FINDINGS


# --------------------------------------------------------------------------
# --report-output
# --------------------------------------------------------------------------


def test_report_output_writes_to_requested_path(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(textwrap.dedent(VULN))
    out = tmp_path / "reports" / "scan.md"

    result = runner.invoke(app, ["scan", str(proj), "--report-output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
    assert "PI-" in out.read_text()


def test_report_defaults_to_cwd_file(tmp_path, monkeypatch):
    """--report keeps its historical default filename (backwards compatible)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(textwrap.dedent(VULN))
    workdir = tmp_path / "wd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    result = runner.invoke(app, ["scan", str(proj), "--report"])
    assert result.exit_code == 0, result.output
    assert (workdir / "palisade-report.md").is_file()


def test_report_to_unwritable_path_is_a_usage_error(tmp_path):
    """A bad output path must be a clean usage error, not a traceback."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(textwrap.dedent(VULN))
    # a path whose parent is an existing *file* cannot be created
    blocker = tmp_path / "blocker"
    blocker.write_text("x")

    result = runner.invoke(app, ["scan", str(proj), "--report-output", str(blocker / "out.md")])
    assert result.exit_code == EXIT_USAGE
    assert "could not write report" in result.output


@pytest.mark.parametrize("flag", ["--ci", "--json"])
def test_healthy_scan_unaffected_by_boundary(tmp_path, flag):
    """Sanity: the common paths still behave exactly as before."""
    proj = tmp_path
    (proj / "app.py").write_text(textwrap.dedent(CLEAN))
    result = runner.invoke(app, ["scan", str(proj), flag])
    assert result.exit_code == 0


# --------------------------------------------------------------------------
# Legacy console encodings (UX-3)
# --------------------------------------------------------------------------


class _Cp1252Stream(io.StringIO):
    """A stream that reports a legacy encoding and refuses non-cp1252 text."""

    encoding = "cp1252"

    def write(self, s: str) -> int:
        s.encode("cp1252")  # raises UnicodeEncodeError, exactly like the real console
        return super().write(s)


def _render(findings_project, encoding_stream):
    from rich.console import Console

    from palisade_sec.report import print_findings
    from palisade_sec.scanner import run_scan

    result = run_scan(findings_project)
    console = Console(file=encoding_stream, highlight=False, safe_box=True, width=100)
    print_findings(console, result.findings, result.files_scanned, [], [], [])
    return encoding_stream.getvalue()


def test_clean_scan_renders_on_legacy_cp1252_console(tmp_path):
    """A clean scan must not die encoding its own success message."""
    (tmp_path / "app.py").write_text(textwrap.dedent(CLEAN))
    out = _render(tmp_path, _Cp1252Stream())
    assert "No LLM injection paths found" in out


def test_findings_render_on_legacy_cp1252_console(tmp_path):
    """The trace arrows must degrade to ASCII rather than raise."""
    (tmp_path / "app.py").write_text(textwrap.dedent(VULN))
    out = _render(tmp_path, _Cp1252Stream())
    assert "source:" in out and "sink:" in out
    assert "\u21b3" not in out


def test_utf8_console_keeps_the_real_glyphs(tmp_path):
    """The fallback must not degrade output on capable terminals."""

    class _Utf8Stream(io.StringIO):
        encoding = "utf-8"

    (tmp_path / "app.py").write_text(textwrap.dedent(VULN))
    out = _render(tmp_path, _Utf8Stream())
    assert "\u21b3" in out


def test_scan_exits_zero_on_legacy_console(tmp_path, monkeypatch):
    """End-to-end: the CLI's own exit code must not depend on the codepage."""
    (tmp_path / "app.py").write_text(textwrap.dedent(CLEAN))

    from palisade_sec.report import terminal

    monkeypatch.setattr(terminal, "_ascii_only", lambda console: True)
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci"])
    assert result.exit_code == 0, result.output
