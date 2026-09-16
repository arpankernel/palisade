"""Seeded rules added in v0.3: PI-HTTP (advisory SSRF) and
PI-FRAMEWORK-EXEC (agent/pipeline wrapper signatures, the PandasAI shape)."""

import textwrap

from palisade_sec.rules import load_rules
from palisade_sec.scanner import run_scan


def _scan(tmp_path, assume_params=False, **files):
    for name, body in files.items():
        (tmp_path / f"{name}.py").write_text(textwrap.dedent(body))
    res = run_scan(tmp_path, assume_params_untrusted=assume_params or None)
    assert res.skipped == []
    return res


def test_five_builtin_rules():
    ids = {r.id for r in load_rules().rules}
    assert {"PI-EXEC", "PI-SHELL", "PI-SQL", "PI-HTTP", "PI-FRAMEWORK-EXEC"} <= ids


# ---------------------------------------------------------------------------
# PI-HTTP
# ---------------------------------------------------------------------------


def test_http_llm_url_flagged_med(tmp_path):
    res = _scan(
        tmp_path,
        app="""
        import requests
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def fetch():
            topic = request.json["topic"]
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": f"Best URL about {topic}?"}]
            )
            url = resp.choices[0].message.content.strip()
            return requests.get(url).text
        """,
    )
    hits = [f for f in res.findings if f.rule_id == "PI-HTTP"]
    assert len(hits) == 1
    assert hits[0].severity == "med"  # advisory by design (PII-1 style)


def test_http_constant_url_silent(tmp_path):
    """LLM output in the payload of a constant-URL request is fine - only
    the URL argument is the sink (taint_args)."""
    res = _scan(
        tmp_path,
        app="""
        import requests
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def summarize():
            topic = request.json["topic"]
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": topic}]
            )
            summary = resp.choices[0].message.content
            requests.post("https://internal.example/api/summaries", json={"s": summary})
        """,
    )
    assert [f for f in res.findings if f.rule_id == "PI-HTTP"] == []


# ---------------------------------------------------------------------------
# PI-FRAMEWORK-EXEC (the PandasAI shape: wrapper LLM -> execution step)
# ---------------------------------------------------------------------------

PANDASAI_SHAPE = """
        class CodePipeline:
            def chat(self, query):
                code = self.generate_code(query)
                return self.execute_code(code)

            def generate_code(self, query):
                prompt = f"Write pandas code for: {query}"
                return self._llm.call_llm(prompt)

            def execute_code(self, code):
                env = {}
                exec(code, env)
                return env.get("result")
"""


def test_framework_wrapper_chain_flagged_in_library_mode(tmp_path):
    res = _scan(tmp_path, assume_params=True, pipeline=PANDASAI_SHAPE)
    hits = [f for f in res.findings if f.rule_id == "PI-FRAMEWORK-EXEC"]
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "high"
    assert f.source.detail == "param:query"
    assert "exec(code" in f.sink.snippet


def test_framework_shape_silent_without_library_mode(tmp_path):
    """No visible untrusted source without library mode: precision holds."""
    res = _scan(tmp_path, pipeline=PANDASAI_SHAPE)
    assert res.findings == []


def test_framework_wrapper_with_app_source(tmp_path):
    """The wrapper signatures also work with ordinary app sources."""
    res = _scan(
        tmp_path,
        app="""
        from flask import request

        class Bot:
            def ask_llm(self, prompt):
                return "generated"

        def handler():
            q = request.json["q"]
            bot = Bot()
            code = bot.ask_llm(q)
            exec(code)
        """,
    )
    hits = [f for f in res.findings if f.rule_id == "PI-FRAMEWORK-EXEC"]
    assert len(hits) == 1
