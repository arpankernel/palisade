"""Output-side safety: what Palisade writes and prints when the scanned repo is
hostile. test_self_security.py proves the scanner never executes or escapes
on the READ side; these prove the WRITE and DISPLAY sides hold too.

All three were reproduced against 0.5.0 by a pre-launch security review.
"""

import os
import textwrap

import pytest
from typer.testing import CliRunner

from palisade_sec.cli import app
from palisade_sec.ir.model import Loc
from palisade_sec.report import to_markdown
from palisade_sec.safe_io import UnsafeOutputPath, write_output

runner = CliRunner()

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


@pytest.fixture
def hostile_repo(tmp_path, monkeypatch):
    """A repo that plants symlinks at every predictable output path, all
    pointing outside itself, and is scanned from inside (the normal usage)."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "rcfile").write_text("ORIGINAL\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(VULN)
    (repo / "palisade-report.md").symlink_to(victim / "rcfile")
    (repo / "palisade-fixes.md").symlink_to(victim / "fixes")
    (repo / "palisade-review.md").symlink_to(victim / "review")
    (repo / ".palisade").symlink_to(victim, target_is_directory=True)
    monkeypatch.chdir(repo)
    return victim


@pytest.mark.parametrize(
    "args",
    [["scan", ".", "--report"], ["fix", "."], ["baseline", "."], ["review", ".", "--report"]],
    ids=["scan-report", "fix", "baseline", "review-report"],
)
def test_outputs_never_write_through_a_planted_symlink(hostile_repo, monkeypatch, args):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    result = runner.invoke(app, args)
    assert result.exit_code == 2, result.output
    assert "refusing to write" in result.output
    # Nothing outside the repo was created or changed.
    assert sorted(os.listdir(hostile_repo)) == ["rcfile"]
    assert (hostile_repo / "rcfile").read_text() == "ORIGINAL\n"


def test_normal_outputs_still_work(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(VULN)
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["scan", ".", "--report"]).exit_code == 0
    assert runner.invoke(app, ["baseline", "."]).exit_code == 0
    assert runner.invoke(app, ["fix", "."]).exit_code == 0
    for name in ("palisade-report.md", ".palisade/baseline.json", "palisade-fixes.md"):
        assert (tmp_path / name).is_file() and not (tmp_path / name).is_symlink()


def test_write_output_refuses_symlinked_parent_dir(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    inside = tmp_path / "work"
    inside.mkdir()
    (inside / "reports").symlink_to(outside, target_is_directory=True)
    monkeypatch.chdir(inside)
    with pytest.raises(UnsafeOutputPath):
        write_output(inside / "reports" / "x.md", "data")
    assert list(outside.iterdir()) == []


# ---------------------------------------------------------------------------
# Display: scanned text is shown, never interpreted
# ---------------------------------------------------------------------------


def test_terminal_control_sequences_are_neutralized_in_snippets():
    """A raw ESC in a scanned string literal must not reach the terminal: it
    could clear lines or paint a fake 'no findings' over a real HIGH."""
    loc = Loc(file="app.py", line=1, snippet='x = "\x1b[2K\x1b[31m fake \x1b]0;t\x07"')
    assert "\x1b" not in loc.snippet and "\x07" not in loc.snippet
    assert "\\x1b" in loc.snippet  # still visible, as an escape


def test_bidi_overrides_are_neutralized():
    """Trojan Source (CVE-2021-42574): the displayed code must match the code."""
    loc = Loc(file="app.py", line=1, snippet="access = 'user\u202e\u2066 // admin\u2069\u2066'")
    assert "\u202e" not in loc.snippet and "\u2066" not in loc.snippet


def test_newline_in_filename_cannot_break_report_structure():
    loc = Loc(file="evil\n### injected.py", line=3)
    assert "\n" not in loc.file


def test_end_to_end_escape_in_scanned_code_never_reaches_output(tmp_path):
    hostile = 'q = request.json["q"] + "\x1b[2K\x1b]0;pwned\x07"'
    body = VULN.replace('q = request.json["q"]', hostile)
    (tmp_path / "app.py").write_text(body)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert "PI-SHELL" in result.output
    assert "\x1b]0;pwned" not in result.output
    assert "\x1b[2K" not in result.output


def test_markdown_code_spans_cannot_be_broken_by_backticks(tmp_path, monkeypatch):
    """A backtick or pipe in a path or snippet must not close the code span or
    open a table cell in a report people share and trust."""
    from palisade_sec.scanner import run_scan

    name = "a`](evil)`|b.py"  # "/" can't appear in a filename; the rest can
    (tmp_path / name).write_text(VULN)
    res = run_scan(tmp_path)
    assert res.findings, "fixture should produce a finding"
    md = to_markdown(res.findings, res.files_scanned, "x")
    heading = next(line for line in md.splitlines() if line.startswith("### "))
    assert heading.count("`") == 2, heading  # exactly one balanced code span
    assert "](evil)" in heading  # shown literally, inside the span
