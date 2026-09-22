"""Downgrade, never silence: only an ALLOWLIST-shaped sanitizer may suppress a
finding. Every other shape named like a validator is bypassable and must
leave a MED "unverified sanitizer" finding.

0.5.0 fully silenced the first two cases below, contradicting the documented
contract. A reader of the launch post is expected to try exactly these.
"""

import textwrap

import pytest

from palisade_sec.scanner import run_scan

PREAMBLE = """
from flask import request
from openai import OpenAI
client = OpenAI()
"""

SINK = """
def handler():
    q = request.json["q"]
    resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
    exec(validate_code(resp.choices[0].message.content))
"""

BYPASSABLE = {
    "substring-denylist": """
        def validate_code(c):
            if "import" in c or "os." in c:
                raise ValueError("blocked")
            return c
    """,
    "denylist-loop": """
        BLOCKED = ["os.", "subprocess", "__import__"]
        def validate_code(c):
            if any(bad in c for bad in BLOCKED):
                raise ValueError("blocked")
            return c
    """,
    "length-check": """
        def validate_code(c):
            if len(c) > 500:
                raise ValueError("too long")
            return c
    """,
    "type-check": """
        def validate_code(c):
            if not isinstance(c, str):
                raise TypeError("not text")
            return c
    """,
    "parse-check": """
        import ast
        def validate_code(c):
            ast.parse(c)
            return c
    """,
}

ALLOWLISTS = {
    "set-membership": """
        ALLOWED = {"print_report()", "summary()"}
        def validate_code(c):
            if c not in ALLOWED:
                raise ValueError("not allowed")
            return c
    """,
    "enum-literal": """
        def validate_code(c):
            if c not in ("print_report()", "summary()"):
                raise ValueError("not allowed")
            return c
    """,
    "fullmatch-in-guard": """
        import re
        def validate_code(c):
            if not re.fullmatch(r"[a-z_]+\\(\\)", c):
                raise ValueError("bad")
            return c
    """,
    "ast-node-allowlist": """
        import ast
        ALLOWED_NODES = (ast.Module, ast.Expr, ast.Call, ast.Name, ast.Load)
        def validate_code(c):
            for node in ast.walk(ast.parse(c)):
                if not isinstance(node, ALLOWED_NODES):
                    raise ValueError("disallowed")
            return c
    """,
}


def _scan(tmp_path, sanitizer: str):
    body = PREAMBLE + textwrap.dedent(sanitizer) + SINK
    (tmp_path / "app.py").write_text(body)
    res = run_scan(tmp_path)
    assert res.skipped == [], res.skipped
    return res


@pytest.mark.parametrize("name", sorted(BYPASSABLE))
def test_bypassable_validator_downgrades_never_silences(tmp_path, name):
    res = _scan(tmp_path, BYPASSABLE[name])
    assert len(res.findings) == 1, f"{name}: a bypassable validator silenced the finding"
    (f,) = res.findings
    assert f.rule_id == "PI-EXEC"
    assert f.severity == "med" and f.risky, (name, f.severity)
    assert [p.kind for p in f.partial_defenses] == ["unverified_sanitizer"]


@pytest.mark.parametrize("name", sorted(ALLOWLISTS))
def test_allowlist_validator_suppresses(tmp_path, name):
    res = _scan(tmp_path, ALLOWLISTS[name])
    assert res.findings == [], f"{name}: a real allowlist should suppress, got {res.findings}"
