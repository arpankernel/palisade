"""Inline suppressions (`palisade: ignore`).

These are deliberately loud: a suppressed finding is still counted and
attributable, and a comment that stops matching anything is reported as
stale. A silent suppression is how a vulnerability quietly comes back.
"""

import textwrap

import pytest

from palisade_sec.scanner import run_scan
from palisade_sec.suppress import parse_suppressions

# NOTE: built by concatenation, not str.format - the source contains
# `{"role": ...}` braces, which format() would try to interpret as fields.
_HEAD = """
    import os
    from flask import request
    from openai import OpenAI

    client = OpenAI()

    def handler():
        q = request.json["q"]
        resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
        os.system(resp.choices[0].message.content)"""


def vuln(tail=""):
    return _HEAD + tail + "\n"


def _scan(tmp_path, source, name="app.py"):
    (tmp_path / name).write_text(textwrap.dedent(source))
    res = run_scan(tmp_path)
    assert res.skipped == [], res.skipped
    return res


def test_baseline_case_is_flagged_without_a_suppression(tmp_path):
    """Control: the fixture really is a finding when nothing silences it."""
    res = _scan(tmp_path, vuln())
    assert [f.rule_id for f in res.findings] == ["PI-SHELL"]
    assert res.suppressed == []


def test_suppression_on_the_sink_line(tmp_path):
    res = _scan(tmp_path, vuln("  # palisade: ignore[PI-SHELL] - sandboxed"))
    assert res.findings == []
    assert len(res.suppressed) == 1
    entry = res.suppressed[0]
    assert entry["rule"] == "PI-SHELL"
    assert entry["reason"] == "sandboxed"
    assert entry["severity"] == "high"


def test_suppression_on_the_line_above(tmp_path):
    # Insert the comment as its own line directly above the sink, preserving
    # the sink's indentation. (Replacing the raw "    os.system(" text would
    # dedent the sink out of the function and destroy the finding entirely.)
    lines = vuln().rstrip("\n").splitlines()
    sink = next(i for i, ln in enumerate(lines) if "os.system(" in ln)
    indent = lines[sink][: len(lines[sink]) - len(lines[sink].lstrip())]
    lines.insert(sink, f"{indent}# palisade: ignore[PI-SHELL] - above the sink")
    res = _scan(tmp_path, "\n".join(lines) + "\n")
    assert res.findings == []
    assert len(res.suppressed) == 1
    assert res.suppressed[0]["reason"] == "above the sink"


def test_wrong_rule_id_does_not_suppress(tmp_path):
    res = _scan(tmp_path, vuln("  # palisade: ignore[PI-EXEC]"))
    assert [f.rule_id for f in res.findings] == ["PI-SHELL"]
    assert res.suppressed == []


def test_bare_ignore_suppresses_any_rule(tmp_path):
    res = _scan(tmp_path, vuln("  # palisade: ignore"))
    assert res.findings == []
    assert len(res.suppressed) == 1


def test_rule_list_suppresses(tmp_path):
    res = _scan(tmp_path, vuln("  # palisade: ignore[PI-EXEC,PI-SHELL]"))
    assert res.findings == []


def test_suppression_is_counted_and_noted_not_silent(tmp_path):
    res = _scan(tmp_path, vuln("  # palisade: ignore[PI-SHELL] - reviewed"))
    assert any("silenced by inline" in n for n in res.notes)


def test_stale_suppression_is_reported(tmp_path):
    (tmp_path / "clean.py").write_text(
        textwrap.dedent(
            """
            def add(a, b):
                return a + b  # palisade: ignore[PI-EXEC] - nothing here
            """
        )
    )
    res = run_scan(tmp_path)
    assert res.findings == []
    assert any("stale" in n for n in res.notes), res.notes


def test_javascript_double_slash_form(tmp_path):
    pytest.importorskip("tree_sitter")
    (tmp_path / "app.js").write_text(
        textwrap.dedent(
            """
            import OpenAI from "openai";
            const client = new OpenAI();
            export async function h(req, res) {
              const r = await client.chat.completions.create({
                messages: [{ role: "user", content: req.body.q }],
              });
              eval(r.choices[0].message.content); // palisade: ignore[PI-EXEC] - trusted
            }
            """
        )
    )
    res = run_scan(tmp_path)
    assert res.findings == []
    assert len(res.suppressed) == 1
    assert res.suppressed[0]["reason"] == "trusted"


def test_suppressed_findings_leave_the_findings_list_but_stay_visible(tmp_path):
    """They must not be reported as findings, and must not vanish either."""
    res = _scan(tmp_path, vuln("  # palisade: ignore[PI-SHELL] - ok"))
    import json

    from palisade_sec.report import to_json

    doc = json.loads(
        to_json(
            res.findings,
            res.files_scanned,
            res.skipped,
            res.warnings,
            res.notes,
            suppressed=res.suppressed,
        )
    )
    assert doc["findings"] == []
    assert doc["summary"]["suppressed_inline"] == 1
    assert doc["suppressions"][0]["rule"] == "PI-SHELL"


@pytest.mark.parametrize(
    "line,rules,reason",
    [
        ("x = 1  # palisade: ignore", None, ""),
        ("x = 1  # palisade: ignore[PI-EXEC]", {"PI-EXEC"}, ""),
        ("x = 1  # palisade: ignore[pi-exec, pi-sql] - why", {"PI-EXEC", "PI-SQL"}, "why"),
        ("x = 1  // palisade: ignore[PI-EXEC]: reason here", {"PI-EXEC"}, "reason here"),
        ("x = 1  # PALISADE: IGNORE", None, ""),
    ],
)
def test_parse_variants(line, rules, reason):
    got = parse_suppressions(line)
    assert 1 in got
    assert (got[1].rules if got[1].rules is None else set(got[1].rules)) == rules
    assert got[1].reason == reason


def test_unrelated_comments_are_not_suppressions():
    assert parse_suppressions("x = 1  # ignore this please") == {}
    assert parse_suppressions("# palisade is a linter") == {}
