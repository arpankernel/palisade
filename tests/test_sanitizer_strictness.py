"""Sanitizer strictness (v0.2): a sanitizer-by-name-only downgrades to MED
"unverified sanitizer" instead of suppressing - unless the resolved
project-local body shows a real allowlist/validation shape, or the pattern
is a trusted framework validator."""

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


def test_unverified_transform_sanitizer_downgrades(tmp_path):
    """A cosmetic .replace() 'sanitizer' (the Vanna shape) must not silence
    the finding - MED 'unverified sanitizer' instead."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        from cleaners import sanitize_output

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            code = sanitize_output(resp.choices[0].message.content)
            exec(code)
        """,
        cleaners="""
        def sanitize_output(code):
            return code.replace("__import__", "")
        """,
    )
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "med" and f.risky
    assert [p.kind for p in f.partial_defenses] == ["unverified_sanitizer"]


def test_verified_guard_body_still_suppresses(tmp_path):
    """A sanitizer whose body raises on invalid input is verified - silent."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        from checks import validate_command

        def handler():
            import os
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            cmd = validate_command(resp.choices[0].message.content)
            os.system(cmd)
        """,
        checks="""
        SAFE_CMDS = ("uptime", "date", "whoami")

        def validate_command(cmd):
            if cmd not in SAFE_CMDS:
                raise ValueError(cmd)
            return cmd
        """,
    )
    assert res.findings == []


def test_verified_membership_guard_call_suppresses(tmp_path):
    """`if is_safe_cmd(x): sink(x)` where the checker body has a membership
    test is verified - silent."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        import os

        SAFE = ("uptime", "date")

        def is_safe_cmd(cmd):
            return cmd in SAFE

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            cmd = resp.choices[0].message.content
            if is_safe_cmd(cmd):
                os.system(cmd)
        """,
    )
    assert res.findings == []


def test_unverified_guard_call_downgrades(tmp_path):
    """`if looks_validated(x): sink(x)` where the checker validates nothing
    downgrades instead of suppressing."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        def looks_validated(code):
            return len(code) > 0

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            code = resp.choices[0].message.content
            if looks_validated(code):
                exec(code)
        """,
    )
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "med" and f.risky
    assert [p.kind for p in f.partial_defenses] == ["unverified_sanitizer"]


def test_unresolvable_external_sanitizer_suppresses(tmp_path):
    """A third-party sanitizer we can't inspect keeps the benefit of the
    doubt (precision over recall); known frameworks are `trusted` in rules."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        from vendorlib import sanitize_html

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            exec(sanitize_html(resp.choices[0].message.content))
        """,
    )
    assert res.findings == []


def test_trusted_framework_still_suppresses(tmp_path):
    """pydantic-style model_validate stays fully trusted (existing FP-1)."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        from schemas import SafeExpr

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            checked = SafeExpr.model_validate_json(resp.choices[0].message.content)
            eval(checked.expr)
        """,
        schemas="""
        class SafeExpr:
            expr: str
        """,
    )
    assert res.findings == []
