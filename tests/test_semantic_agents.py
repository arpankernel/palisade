"""AgentGraph extraction is deterministic and offline. Given a multi-agent app,
it must recover the nodes (with the capabilities their tools hold), the handoff
edges, the entry agents, and which dangerous agents are reachable across a
handoff. No network, no judgment."""

from __future__ import annotations

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.agents import build_agent_graph

# OpenAI Agents SDK-style multi-agent app: a triage agent hands off to a writer
# (which can delete files) and a researcher (which makes network calls).
SRC = """
import shutil
import requests
from agents import Agent, function_tool


@function_tool
def delete_files(path: str):
    shutil.rmtree(path)


@function_tool
def fetch(url: str):
    return requests.get(url)


@function_tool
def greet(name: str) -> str:
    return f"hi {name}"


writer = Agent(name="writer", tools=[delete_files])
researcher = Agent(name="researcher", tools=[fetch])
helper = Agent(name="helper", tools=[greet])
triage = Agent(name="triage", tools=[], handoffs=[writer, researcher])
"""


def _graph(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return build_agent_graph([mod])


def test_nodes_and_capabilities():
    g = _graph(SRC)
    assert set(g.nodes) == {"writer", "researcher", "helper", "triage"}
    assert g.nodes["writer"].capabilities == ["file_write"]
    assert g.nodes["researcher"].capabilities == ["network"]
    assert g.nodes["helper"].capabilities == []
    assert g.nodes["triage"].tools == []


def test_handoff_edges():
    g = _graph(SRC)
    edges = {(e.src, e.dst) for e in g.edges}
    assert edges == {("triage", "writer"), ("triage", "researcher")}


def test_entry_nodes_are_roots():
    g = _graph(SRC)
    # writer/researcher are handoff targets; triage and helper are roots.
    assert g.entry_nodes() == ["helper", "triage"]


def test_dangerous_reach_requires_crossing_a_handoff():
    g = _graph(SRC)
    reach = {(r["from"], r["to"]) for r in g.dangerous_reach()}
    assert reach == {("triage", "writer"), ("triage", "researcher")}


def test_standalone_dangerous_agent_is_not_a_multi_agent_reach():
    # A dangerous agent with no incoming/outgoing handoff is its own entry and
    # reaches nothing, so it is not a cross-agent reach (precision-first).
    src = (
        "import shutil\n"
        "from agents import Agent, function_tool\n"
        "@function_tool\n"
        "def wipe(p):\n    shutil.rmtree(p)\n"
        "solo = Agent(name='solo', tools=[wipe])\n"
    )
    g = _graph(src)
    assert g.nodes["solo"].capabilities == ["file_write"]
    assert g.dangerous_reach() == []


def test_empty_project_has_empty_graph():
    g = _graph("x = 1 + 1\n")
    assert g.nodes == {}
    assert g.edges == []
    assert g.dangerous_reach() == []


# -- total check: edge cases -------------------------------------------------


def test_agents_defined_inside_a_function():
    src = (
        "import shutil\n"
        "from agents import Agent, function_tool\n"
        "@function_tool\n"
        "def wipe(p):\n    shutil.rmtree(p)\n"
        "def build():\n"
        "    w = Agent(name='w', tools=[wipe])\n"
        "    t = Agent(name='t', tools=[], handoffs=[w])\n"
        "    return t\n"
    )
    g = _graph(src)
    assert set(g.nodes) == {"w", "t"}
    assert {(e.src, e.dst) for e in g.edges} == {("t", "w")}
    assert g.nodes["w"].capabilities == ["file_write"]


def test_multi_hop_reachability():
    src = (
        "import shutil\n"
        "from agents import Agent, function_tool\n"
        "@function_tool\n"
        "def wipe(p):\n    shutil.rmtree(p)\n"
        "c = Agent(name='c', tools=[wipe])\n"
        "b = Agent(name='b', tools=[], handoffs=[c])\n"
        "a = Agent(name='a', tools=[], handoffs=[b])\n"
    )
    g = _graph(src)
    assert g.entry_nodes() == ["a"]
    assert g.reachable_from("a") == {"b", "c"}
    reach = {(r["from"], r["to"]) for r in g.dangerous_reach()}
    assert reach == {("a", "c")}  # a reaches the dangerous agent two hops away


def test_wrapper_handoff_form():
    # handoffs=[handoff(writer)] should still yield the edge.
    src = (
        "import shutil\n"
        "from agents import Agent, handoff, function_tool\n"
        "@function_tool\n"
        "def wipe(p):\n    shutil.rmtree(p)\n"
        "writer = Agent(name='writer', tools=[wipe])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[handoff(writer)])\n"
    )
    g = _graph(src)
    assert {(e.src, e.dst) for e in g.edges} == {("triage", "writer")}


def test_dangling_handoff_edge_is_dropped():
    # A handoff to an agent we never saw constructed is not an edge (precision).
    src = "from agents import Agent\ntriage = Agent(name='triage', tools=[], handoffs=[ghost])\n"
    g = _graph(src)
    assert g.edges == []


def test_map_json_carries_agent_graph():
    from palisade_sec.semantic.inventory import build_map

    mod = PythonFrontend().lower_file("t.py", "t.py", SRC)
    assert not isinstance(mod, ParseFailure)
    d = build_map([mod]).to_dict(1)
    assert "agent_graph" in d
    assert d["summary"]["agent_handoffs"] == 2
    ag = d["agent_graph"]
    assert {n["name"] for n in ag["nodes"]} == {"writer", "researcher", "helper", "triage"}
    assert {(e["src"], e["dst"]) for e in ag["edges"]} == {
        ("triage", "writer"),
        ("triage", "researcher"),
    }
