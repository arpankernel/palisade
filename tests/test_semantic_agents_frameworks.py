from __future__ import annotations

import pytest

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.agents import build_agent_graph


def _graph(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return build_agent_graph([mod])


# -- LangGraph ---------------------------------------------------------------

LANGGRAPH = """
import shutil
from langgraph.graph import StateGraph, START, END


def researcher(state):
    return state


def ops(state):
    shutil.rmtree(state["path"])


g = StateGraph(dict)
g.add_node("researcher", researcher)
g.add_node("ops", ops)
g.add_edge(START, "researcher")
g.add_edge("researcher", "ops")
g.add_edge("ops", END)
"""


def test_langgraph_nodes_and_capabilities_from_function_body():
    g = _graph(LANGGRAPH)
    assert set(g.nodes) == {"researcher", "ops"}
    # ops's capability comes from walking its node function body.
    assert g.nodes["ops"].capabilities == ["file_write"]
    assert g.nodes["researcher"].capabilities == []


def test_langgraph_edges_drop_start_end():
    g = _graph(LANGGRAPH)
    assert {(e.src, e.dst) for e in g.edges} == {("researcher", "ops")}
    assert g.entry_nodes() == ["researcher"]
    assert {(r["from"], r["to"]) for r in g.dangerous_reach()} == {("researcher", "ops")}


@pytest.mark.parametrize(
    "extra, expect_alias, expect_edges",
    [
        pytest.param(
            "app = g.compile()\n",
            {"app": "researcher"},
            {("researcher", "ops")},
            id="compile-aliases-start-node",
        ),
        pytest.param(
            # An unrelated router present in the module must not confuse
            # entry-point resolution for a graph that never calls it.
            "def route(state):\n    return 'ops'\napp = g.compile()\n",
            {"app": "researcher"},
            {("researcher", "ops")},
            id="compile-unaffected-by-unrelated-router",
        ),
    ],
)
def test_langgraph_compile_entry_point_resolution(extra, expect_alias, expect_edges):
    g = _graph(LANGGRAPH + "\n" + extra)
    assert g.entry_aliases == expect_alias
    assert {(e.src, e.dst) for e in g.edges} == expect_edges


def test_langgraph_set_entry_point_aliases_compile():
    src = (
        "import shutil\n"
        "from langgraph.graph import StateGraph\n"
        "def triage(state):\n    return state\n"
        "def wipe(state):\n    shutil.rmtree(state['p'])\n"
        "g = StateGraph(dict)\n"
        "g.add_node('triage', triage)\n"
        "g.add_node('wipe', wipe)\n"
        "g.set_entry_point('triage')\n"
        "g.add_edge('triage', 'wipe')\n"
        "app = g.compile()\n"
    )
    g = _graph(src)
    assert g.entry_aliases == {"app": "triage"}
    assert {(e.src, e.dst) for e in g.edges} == {("triage", "wipe")}


@pytest.mark.parametrize(
    "path_map, expect_edges",
    [
        pytest.param(
            "{'escalate': 'escalate', '__end__': '__end__'}",
            {("triage", "escalate", "conditional_handoff")},
            id="reaches-dict-values",
        ),
        pytest.param(
            # path_map targets a node id that was never add_node'd -
            # precision-first, not a guess.
            "{'x': 'ghost'}",
            set(),
            id="unknown-target-is-dropped",
        ),
    ],
)
def test_langgraph_conditional_edges(path_map, expect_edges):
    src = (
        "import shutil\n"
        "from langgraph.graph import StateGraph, START\n"
        "def triage(state):\n    return state\n"
        "def escalate(state):\n    shutil.rmtree(state['p'])\n"
        "def route(state):\n    return 'escalate' if state['risky'] else '__end__'\n"
        "g = StateGraph(dict)\n"
        "g.add_node('triage', triage)\n"
        "g.add_node('escalate', escalate)\n"
        "g.add_edge(START, 'triage')\n"
        f"g.add_conditional_edges('triage', route, {path_map})\n"
    )
    g = _graph(src)
    assert {(e.src, e.dst, e.kind) for e in g.edges} == expect_edges
    if expect_edges:
        assert {(r["from"], r["to"]) for r in g.dangerous_reach()} == {("triage", "escalate")}


# -- CrewAI ------------------------------------------------------------------

CREWAI_SEQ = """
import subprocess
from crewai import Agent, Crew, Process
from crewai.tools import tool


@tool
def shell(cmd):
    subprocess.run(cmd, shell=True)


researcher = Agent(role="researcher", tools=[])
executor = Agent(role="executor", tools=[shell])
crew = Crew(agents=[researcher, executor], process=Process.sequential)
"""


def test_crewai_sequential_chains_edges():
    g = _graph(CREWAI_SEQ)
    assert set(g.nodes) == {"researcher", "executor"}
    assert g.nodes["executor"].capabilities == ["shell"]
    assert {(e.src, e.dst) for e in g.edges} == {("researcher", "executor")}
    assert {(r["from"], r["to"]) for r in g.dangerous_reach()} == {("researcher", "executor")}


def test_crewai_hierarchical_connects_manager_to_rest():
    src = (
        "import subprocess\n"
        "from crewai import Agent, Crew, Process\n"
        "from crewai.tools import tool\n"
        "@tool\n"
        "def shell(cmd):\n    subprocess.run(cmd, shell=True)\n"
        "manager = Agent(role='manager', tools=[])\n"
        "a = Agent(role='a', tools=[shell])\n"
        "b = Agent(role='b', tools=[])\n"
        "crew = Crew(agents=[manager, a, b], process=Process.hierarchical)\n"
    )
    g = _graph(src)
    assert {(e.src, e.dst) for e in g.edges} == {("manager", "a"), ("manager", "b")}


def test_crew_with_one_agent_has_no_edges():
    src = (
        "from crewai import Agent, Crew\n"
        "solo = Agent(role='solo', tools=[])\n"
        "crew = Crew(agents=[solo])\n"
    )
    g = _graph(src)
    assert g.edges == []


@pytest.mark.parametrize(
    "src, expect_alias",
    [
        pytest.param(CREWAI_SEQ, {"crew": "researcher"}, id="sequential-aliases-first-agent"),
        pytest.param(
            "import subprocess\n"
            "from crewai import Agent, Crew, Process\n"
            "from crewai.tools import tool\n"
            "@tool\n"
            "def shell(cmd):\n    subprocess.run(cmd, shell=True)\n"
            "manager = Agent(role='manager', tools=[])\n"
            "a = Agent(role='a', tools=[shell])\n"
            "crew = Crew(agents=[manager, a], process=Process.hierarchical)\n",
            {"crew": "manager"},
            id="hierarchical-aliases-manager",
        ),
        pytest.param(
            # A single-agent crew has no chain edges, but kickoff() still
            # has to resolve to that one agent to be recognized as a run
            # site at all.
            "from crewai import Agent, Crew\n"
            "solo = Agent(role='solo', tools=[])\n"
            "crew = Crew(agents=[solo])\n",
            {"crew": "solo"},
            id="single-agent-still-aliases",
        ),
    ],
)
def test_crew_entry_point_aliasing(src, expect_alias):
    g = _graph(src)
    assert g.entry_aliases == expect_alias


# -- mixed / regression: the OpenAI Agents SDK shape still works -------------


def test_openai_agents_shape_unaffected():
    src = (
        "import shutil\n"
        "from agents import Agent, function_tool\n"
        "@function_tool\n"
        "def wipe(p):\n    shutil.rmtree(p)\n"
        "w = Agent(name='w', tools=[wipe])\n"
        "t = Agent(name='t', tools=[], handoffs=[w])\n"
    )
    g = _graph(src)
    assert {(e.src, e.dst) for e in g.edges} == {("t", "w")}
    assert g.nodes["w"].capabilities == ["file_write"]
