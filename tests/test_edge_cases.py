"""Edge-case tests from the PRD: false-negative guards (must STILL catch),
false-positive guards (must NOT flag), and robustness."""

import textwrap

from palisade_sec.scanner import run_scan


def scan_files(tmp_path, **files):
    """Keys are file paths with `__py` for `.py` and `__` for `/`:
    tests__test_agent__py -> tests/test_agent.py"""
    for name, body in files.items():
        if name.endswith("__py"):
            name = name[: -len("__py")] + ".py"
        p = tmp_path / name.replace("__", "/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return run_scan(tmp_path)


LLM_PREAMBLE = """
    from openai import OpenAI
    from flask import request
    client = OpenAI()
"""


# ---------------------------------------------------------------------------
# must STILL catch (false-negative guards)
# ---------------------------------------------------------------------------


def test_fn_aliased_imports(tmp_path):
    """FN-7: aliased sink + aliased client still detected."""
    res = scan_files(
        tmp_path,
        shellalias__py="""
        import subprocess as sp
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def handler():
            goal = request.json["goal"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": goal}])
            cmd = resp.choices[0].message.content
            sp.run(cmd, shell=True)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-SHELL"]


def test_fn_from_import_sink_alias(tmp_path):
    res = scan_files(
        tmp_path,
        app__py="""
        from os import system as launch
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def go():
            q = request.args.get("q")
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            launch(resp.choices[0].message.content)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-SHELL"]


def test_fn_string_building_variants(tmp_path):
    """FN-2: taint through %, .format, +, .join."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def fmt():
            q = request.json["q"]
            prompt = "Answer: {}".format(q)
            prompt = "prefix" + prompt
            prompt = "%s suffix" % prompt
            prompt = " ".join([prompt, "end"])
            resp = client.chat.completions.create(messages=[{"role": "user", "content": prompt}])
            exec(resp.choices[0].message.content)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


def test_fn_json_loads_field(tmp_path):
    """FN-9: json.loads(output)["cmd"] reaching a sink."""
    res = scan_files(
        tmp_path,
        app__py="""
        import json
        import os
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def tool_call():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            payload = json.loads(resp.choices[0].message.content)
            os.system(payload["cmd"])
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-SHELL"]


def test_fn_self_field_flow(tmp_path):
    """FN-5: self.x = tainted in one method, sink via self.x in another."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        class Agent:
            def plan(self):
                q = request.json["q"]
                resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
                self.code = resp.choices[0].message.content

            def act(self):
                exec(self.code)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


def test_fn_await_and_return(tmp_path):
    """FN-4: taint through await and returned values."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        async def ask(prompt):
            resp = await client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}]
            )
            return resp.choices[0].message.content

        async def handler():
            q = request.json["q"]
            code = await ask(q)
            exec(code)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


def test_fn_anthropic_shape(tmp_path):
    """FN-6: anthropic response shape resp.content[0].text."""
    res = scan_files(
        tmp_path,
        app__py="""
        import anthropic
        from flask import request
        client = anthropic.Anthropic()

        def handler():
            q = request.json["q"]
            resp = client.messages.create(
                model="claude-sonnet-5",
                messages=[{"role": "user", "content": q}],
            )
            exec(resp.content[0].text)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


def test_fn_input_and_sys_argv_sources(tmp_path):
    res = scan_files(
        tmp_path,
        cli__py="""
        import sys
        from openai import OpenAI
        client = OpenAI()

        def main():
            task = input("task> ")
            arg = sys.argv[1]
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": task + arg}]
            )
            eval(resp.choices[0].message.content)
        """,
    )
    # two distinct sources (input, sys.argv) reach the sink: one trace each
    assert {f.rule_id for f in res.findings} == {"PI-EXEC"}
    assert {f.source.detail for f in res.findings} == {"input", "sys.argv"}


def test_fn_dict_tuple_comprehension_flow(tmp_path):
    """FN-3: through dict/list access, unpacking, comprehensions."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def handler():
            data = {"q": request.json["q"]}
            items = [v for v in data.values()]
            first, = items
            resp = client.chat.completions.create(messages=[{"role": "user", "content": first}])
            parts = [line for line in resp.choices[0].message.content.splitlines()]
            exec("\\n".join(parts))
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


# ---------------------------------------------------------------------------
# must NOT flag (false-positive guards)
# ---------------------------------------------------------------------------


def test_fp_no_untrusted_source(tmp_path):
    """FP-4: constant developer prompt -> LLM -> exec is not a finding."""
    res = scan_files(
        tmp_path,
        app__py="""
        from openai import OpenAI
        client = OpenAI()

        def cron():
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": "print the date"}]
            )
            exec(resp.choices[0].message.content)
        """,
    )
    assert res.findings == []


def test_fp_source_to_sink_without_llm(tmp_path):
    """Untrusted input straight into exec is Bandit's job, not ours."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request

        def handler():
            exec(request.json["code"])
        """,
    )
    assert res.findings == []


def test_fp_pydantic_validation(tmp_path):
    """FP-1: pydantic validation on the path suppresses."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        from schemas import SafeExpr
        client = OpenAI()

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            checked = SafeExpr.model_validate_json(resp.choices[0].message.content)
            eval(checked.expr)
        """,
        schemas__py="""
        class SafeExpr:
            expr: str
        """,
    )
    assert res.findings == []


def test_fp_int_cast(tmp_path):
    """FP-3: output constrained to int before the sink."""
    res = scan_files(
        tmp_path,
        app__py="""
        import os
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            n = int(resp.choices[0].message.content)
            os.system("renice %d self" % n)
        """,
    )
    assert res.findings == []


def test_fp_test_files_excluded_by_default(tmp_path):
    res = scan_files(
        tmp_path,
        tests__test_agent__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def test_it():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            exec(resp.choices[0].message.content)
        """,
    )
    assert res.findings == []
    assert res.files_scanned == 0


# ---------------------------------------------------------------------------
# robustness
# ---------------------------------------------------------------------------


def test_rb_parse_error_skipped_not_crash(tmp_path):
    res = scan_files(
        tmp_path,
        broken__py="""
        def broken(:
        """,
        ok__py="""
        import os
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            os.system(resp.choices[0].message.content)
        """,
    )
    assert len(res.skipped) == 1 and "broken.py" in res.skipped[0]
    assert [f.rule_id for f in res.findings] == ["PI-SHELL"]


def test_rb_venv_excluded(tmp_path):
    res = scan_files(
        tmp_path,
        **{
            ".venv__lib__bad__py": """
            from flask import request
            from openai import OpenAI
            client = OpenAI()
            def h():
                q = request.json["q"]
                r = client.chat.completions.create(messages=[{"role": "user", "content": q}])
                exec(r.choices[0].message.content)
            """,
        },
    )
    assert res.files_scanned == 0
    assert res.findings == []


def test_rb_invalid_custom_rules_reported_not_crash(tmp_path):
    rules_dir = tmp_path / "myrules"
    rules_dir.mkdir()
    (rules_dir / "bad.yaml").write_text("id: [not, a, string}")
    (tmp_path / "empty.py").write_text("x = 1\n")
    res = run_scan(tmp_path, rules_dir=str(rules_dir))
    assert any("bad.yaml" in w for w in res.warnings)
    assert res.findings == []


def test_gitignore_honored(tmp_path):
    (tmp_path / ".gitignore").write_text("generated/\n")
    res = scan_files(
        tmp_path,
        generated__gen__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()
        def h():
            q = request.json["q"]
            r = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            exec(r.choices[0].message.content)
        """,
    )
    assert res.files_scanned == 0
    assert res.findings == []


def test_partial_defense_call_downgrades(tmp_path):
    """FN-11 variant: a denylist *call* transform keeps the finding at MED."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        from safety import strip_denylisted
        client = OpenAI()

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            code = strip_denylisted(resp.choices[0].message.content)
            exec(code)
        """,
        safety__py="""
        def strip_denylisted(code):
            return code.replace("os.system", "")
        """,
    )
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "PI-EXEC" and f.severity == "med" and f.risky


# ---------------------------------------------------------------------------
# safety of the tool itself (SF-1: critical, non-negotiable)
# ---------------------------------------------------------------------------


def test_sf_never_executes_scanned_code(tmp_path):
    """Scanning must never run the target's code — module level included."""
    marker = tmp_path / "pwned.txt"
    (tmp_path / "evil.py").write_text(
        f"open({str(marker)!r}, 'w').write('executed')\nraise SystemExit(99)\n"
    )
    res = run_scan(tmp_path)
    assert res.files_scanned == 1
    assert not marker.exists(), "scanner executed scanned code — critical safety violation"


# ---------------------------------------------------------------------------
# v0.2 engine precision (stub propagation, sink taint_args, accumulators)
# ---------------------------------------------------------------------------


def test_fp_exec_env_dict_not_flagged(tmp_path):
    """exec's globals/locals dicts are not code: tainted data there is not a
    finding (taint_args: [0] on the exec sink)."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            answer = resp.choices[0].message.content
            env = {"answer": answer}
            exec("print(answer)", globals(), env)
        """,
    )
    assert res.findings == []


def test_fn_stub_method_taint_propagates(tmp_path):
    """An abstract stub (`...` body) is a placeholder, not a taint sink —
    calls through it propagate (the real Vanna system_message shape)."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def wrap_message(text):
            ...

        def handler():
            q = request.json["q"]
            msg = wrap_message(q)
            resp = client.chat.completions.create(messages=[msg])
            exec(resp.choices[0].message.content)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


def test_fn_append_accumulator_flow(tmp_path):
    """x.append(tainted) taints x (the Vanna _extract_python_code shape)."""
    res = scan_files(
        tmp_path,
        app__py="""
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def handler():
            parts = []
            parts.append(request.json["q"])
            resp = client.chat.completions.create(
                messages=[{"role": "user", "content": "\\n".join(parts)}]
            )
            exec(resp.choices[0].message.content)
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
