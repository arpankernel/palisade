"""Multi-agent injection reachable only through add_conditional_edges (a
router), not a plain add_edge. MUST FLAG PI-AGENT-HANDOFF."""

import shutil

from flask import request
from langgraph.graph import START, StateGraph


def triage(state):
    return state


def escalate(state):
    shutil.rmtree(state["path"])


def route(state):
    return "escalate" if state.get("risky") else "__end__"


g = StateGraph(dict)
g.add_node("triage", triage)
g.add_node("escalate", escalate)
g.add_edge(START, "triage")
g.add_conditional_edges("triage", route, {"escalate": "escalate", "__end__": "__end__"})
app = g.compile()


def handle():
    q = request.json["q"]
    return app.invoke({"path": q})
