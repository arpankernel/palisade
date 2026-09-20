"""Soundness regressions from the audit fix pass: cases the engine used to
miss (drop to no-finding) because a sink guard or control-flow join was wrong.
Each here MUST flag - a miss is a silent false negative on a real path."""

import textwrap

from palisade_sec.scanner import run_scan


def _scan(tmp_path, **files):
    for name, body in files.items():
        (tmp_path / f"{name}.py").write_text(textwrap.dedent(body))
    res = run_scan(tmp_path)
    assert res.skipped == [], f"fixture must parse cleanly: {res.skipped}"
    return res


PREAMBLE = """
        from flask import request
        from openai import OpenAI
        client = OpenAI()
"""


def test_empty_params_tuple_keeps_sql_sink_armed(tmp_path):
    """`cursor.execute(sql, ())` is not parameterized - the empty tuple binds
    nothing, so the tainted SQL string is what executes. Must flag HIGH."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        import sqlite3

        def handler(cur):
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            sql = "SELECT * FROM t WHERE x = '" + resp.choices[0].message.content + "'"
            cur.execute(sql, ())
        """,
    )
    assert len(res.findings) == 1, [f.rule_id for f in res.findings]
    f = res.findings[0]
    assert f.rule_id == "PI-SQL"
    assert f.severity == "high"


def test_empty_params_kwarg_keeps_sql_sink_armed(tmp_path):
    """`execute(sql, params={})` binds nothing either - still armed."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        def handler(cur):
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            sql = "SELECT * FROM t WHERE x = '" + resp.choices[0].message.content + "'"
            cur.execute(sql, parameters={})
        """,
    )
    assert len(res.findings) == 1, [f.rule_id for f in res.findings]
    assert res.findings[0].rule_id == "PI-SQL"


def test_try_except_join_does_not_lose_taint(tmp_path):
    """`try: code = <llm> except: code = "safe"` - the try path is
    attacker-controlled and fires unless the API call errors. A handler's clean
    reassignment must not erase the try-body taint (control-flow join)."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        def handler():
            q = request.json["q"]
            try:
                resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
                code = resp.choices[0].message.content
            except Exception:
                code = "safe"
            exec(code)
        """,
    )
    assert len(res.findings) == 1, [f.rule_id for f in res.findings]
    f = res.findings[0]
    assert f.rule_id == "PI-EXEC"
    assert f.severity == "high"
