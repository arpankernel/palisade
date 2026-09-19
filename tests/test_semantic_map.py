"""The AI System Map is deterministic and offline: given source, it inventories
the whole AI surface with no network and no TypeSafe. These tests lock what the
`map` command sees."""

from __future__ import annotations

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.inventory import build_map

SRC = '''
from openai import OpenAI
from langchain.agents import initialize_agent
from langchain.tools import tool
import shutil

client = OpenAI()


def ask(user_q):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_q}],
    )


def ask_static():
    return client.chat.completions.create(model="gpt-4o", system="be concise")


def build(tools, llm):
    return initialize_agent(tools, llm, allow_dangerous_code=True)


def search(store, q):
    return store.similarity_search(q)


@tool
def wipe(path):
    "Delete a directory."
    shutil.rmtree(path)
'''


def _lower(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return [mod]


def test_map_counts_the_ai_surface():
    m = build_map(_lower(SRC))
    s = m.summary()
    assert s["llm_calls"] == 2
    assert s["agents"] == 1
    assert s["retrieval"] == 1
    assert s["tools"] == 1
    assert s["config_flags"] == 1  # allow_dangerous_code=True


def test_map_extracts_model_and_provider():
    m = build_map(_lower(SRC))
    models = {a.detail.get("model") for a in m.llm_calls}
    providers = {a.detail.get("provider") for a in m.llm_calls}
    assert "gpt-4o" in models
    assert providers == {"openai"}


def test_map_distinguishes_static_and_dynamic_prompts():
    m = build_map(_lower(SRC))
    dynamic = [p for p in m.prompts if p.detail["dynamic"]]
    static = [p for p in m.prompts if not p.detail["dynamic"]]
    assert dynamic and static  # messages=[...] is dynamic; system="..." is static
    assert any(p.detail["arg"] == "messages" for p in dynamic)
    assert any(p.detail["arg"] == "system" for p in static)


def test_map_flags_dangerous_config():
    m = build_map(_lower(SRC))
    assert len(m.config_flags) == 1
    assert m.config_flags[0].detail["flag"] == "allow_dangerous_code"


def test_map_tool_carries_capabilities():
    m = build_map(_lower(SRC))
    tool = m.tools[0]
    assert tool.name == "wipe"
    assert tool.detail["capabilities"] == ["file_write"]


def test_map_render_is_markup_safe():
    # Square brackets are rich markup; model info must survive rendering.
    from io import StringIO

    from rich.console import Console

    from palisade_sec.semantic.inventory import print_map

    m = build_map(_lower(SRC))
    buf = StringIO()
    print_map(Console(file=buf, width=200, highlight=False), m, 1)
    out = buf.getvalue()
    assert "gpt-4o" in out
    assert "openai" in out


def test_empty_project_is_empty_map():
    m = build_map(_lower("x = 1 + 1\n"))
    assert m.all() == []
    assert m.summary()["llm_calls"] == 0
