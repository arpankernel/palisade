"""Phase 2: framework adapters. The AgentGraph must recover topology from
LangGraph (`add_node`/`add_edge`) and CrewAI (`Crew(agents=, process=)`), not
just the OpenAI Agents SDK kwarg shape."""

from __future__ import annotations

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
