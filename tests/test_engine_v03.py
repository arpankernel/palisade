"""v0.3 engine features: FastAPI/decorator sources, class-hierarchy method
resolution, and sanitizer body-verification refinements."""

import textwrap

from palisade_sec.scanner import run_scan


def _scan(tmp_path, **files):
    for name, body in files.items():
        (tmp_path / f"{name}.py").write_text(textwrap.dedent(body))
    res = run_scan(tmp_path)
    assert res.skipped == [], f"fixture must parse cleanly: {res.skipped}"
    return res


# ---------------------------------------------------------------------------
# FastAPI / decorator sources
# ---------------------------------------------------------------------------

FASTAPI_VULN = """
        from fastapi import FastAPI
        from openai import OpenAI

        app = FastAPI()
        client = OpenAI()

        @app.post("/agent")
        async def run_agent(goal: str):
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": goal}]
            )
            exec(resp.choices[0].message.content)
            return {"status": "done"}
"""


def test_fastapi_route_param_flagged(tmp_path):
    res = _scan(tmp_path, app=FASTAPI_VULN)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "PI-EXEC" and f.severity == "high"
    assert f.source.detail == "param:goal"


def test_fastapi_pydantic_body_field_flagged(tmp_path):
    res = _scan(
        tmp_path,
        app="""
        from fastapi import APIRouter
        from openai import OpenAI
        from models import AgentRequest

        router = APIRouter()
        client = OpenAI()

        @router.post("/agent")
        async def run_agent(req: AgentRequest):
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": req.goal}]
            )
            exec(resp.choices[0].message.content)
        """,
        models="""
        class AgentRequest:
            goal: str
        """,
    )
    assert len(res.findings) == 1
    assert res.findings[0].source.detail == "param:req"


def test_undecorated_function_params_still_clean(tmp_path):
    """Without a route decorator (and without library mode), params are
    trusted — the decorator is what makes it an entry point."""
    res = _scan(tmp_path, app=FASTAPI_VULN.replace('@app.post("/agent")\n        ', ""))
    assert res.findings == []


def test_route_with_constant_prompt_silent(tmp_path):
    res = _scan(
        tmp_path,
        app="""
        from fastapi import FastAPI
        from openai import OpenAI

        app = FastAPI()
        client = OpenAI()

        @app.get("/report")
        def report(fmt: str):
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": "summarize yesterday"}]
            )
            exec(resp.choices[0].message.content)
        """,
    )
    assert res.findings == []


def test_requests_post_not_treated_as_source(tmp_path):
    """The decorator patterns (*.post etc.) must never match ordinary calls
    like requests.post — they apply to decorators only."""
    res = _scan(
        tmp_path,
        app="""
        import requests
        from openai import OpenAI
        client = OpenAI()

        def sync_job():
            data = requests.post("https://internal/api").json()
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": data["prompt"]}]
            )
            exec(resp.choices[0].message.content)
        """,
    )
    assert res.findings == []


# ---------------------------------------------------------------------------
# class-hierarchy method resolution
# ---------------------------------------------------------------------------


def test_llm_in_unique_subclass_resolved(tmp_path):
    """Template method in the base, single provider subclass implements the
    LLM hook: the hop is now visible across the hierarchy."""
    res = _scan(
        tmp_path,
        base="""
        from flask import request

        class AgentBase:
            def handle(self):
                q = request.json["q"]
                code = self.complete(q)
                exec(code)

            def complete(self, prompt):
                raise NotImplementedError
        """,
        provider="""
        from base import AgentBase
        from openai import OpenAI

        client = OpenAI()

        class OpenAIAgent(AgentBase):
            def complete(self, prompt):
                resp = client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    assert res.findings[0].llm.file == "provider.py"


def test_ambiguous_subclass_impls_not_resolved(tmp_path):
    """Two provider implementations: ambiguous, so precision wins and the
    call stays unresolved (stub propagation applies, no LLM hop)."""
    res = _scan(
        tmp_path,
        base="""
        from flask import request

        class AgentBase:
            def handle(self):
                q = request.json["q"]
                code = self.complete(q)
                exec(code)

            def complete(self, prompt):
                raise NotImplementedError
        """,
        providers="""
        from base import AgentBase
        from openai import OpenAI

        client = OpenAI()

        class OpenAIAgent(AgentBase):
            def complete(self, prompt):
                resp = client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content

        class EchoAgent(AgentBase):
            def complete(self, prompt):
                return "print('hello')"
        """,
    )
    assert res.findings == []


def test_method_inherited_from_base_resolved(tmp_path):
    """Subclass calls self.ask_llm() defined in its base class."""
    res = _scan(
        tmp_path,
        app="""
        from flask import request
        from openai import OpenAI

        client = OpenAI()

        class LLMMixin:
            def ask_llm(self, prompt):
                resp = client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content

        class Runner(LLMMixin):
            def go(self):
                q = request.json["q"]
                exec(self.ask_llm(q))
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


# ---------------------------------------------------------------------------
# sanitizer body-verification refinements
# ---------------------------------------------------------------------------

PREAMBLE = """
        from flask import request
        from openai import OpenAI
        client = OpenAI()
"""


def test_raise_in_except_counts_as_validation(tmp_path):
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        import ast

        def validate_snippet(code):
            try:
                ast.parse(code)
            except SyntaxError:
                raise ValueError("not python")
            return code

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            exec(validate_snippet(resp.choices[0].message.content))
        """,
    )
    assert res.findings == []


def test_regex_fullmatch_counts_as_validation(tmp_path):
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        import os
        import re

        def validate_host(name):
            return re.fullmatch(r"[a-z0-9.-]+", name)

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            host = resp.choices[0].message.content
            if validate_host(host):
                os.system("ping -c 1 " + host)
        """,
    )
    assert res.findings == []


def test_delegating_sanitizer_verified_one_level(tmp_path):
    """validate() that only forwards to a real checker is still verified."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        SAFE = ("uptime", "date")

        def _check(cmd):
            if cmd not in SAFE:
                raise ValueError(cmd)
            return cmd

        def validate_cmd(cmd):
            return _check(cmd)

        def handler():
            import os
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            os.system(validate_cmd(resp.choices[0].message.content))
        """,
    )
    assert res.findings == []


def test_transform_only_sanitizer_still_downgrades(tmp_path):
    """The refinements must not weaken the core rule: a transform-only body
    stays unverified."""
    res = _scan(
        tmp_path,
        app=PREAMBLE
        + """
        def sanitize_code(code):
            return code.strip().replace("import os", "")

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            exec(sanitize_code(resp.choices[0].message.content))
        """,
    )
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "med" and f.risky
    assert [p.kind for p in f.partial_defenses] == ["unverified_sanitizer"]
