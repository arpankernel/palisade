"""Multi-agent injection via a compiled LangGraph's .invoke(), not an
individual node function called directly. MUST FLAG PI-AGENT-HANDOFF."""

import shutil

from flask import request
from langgraph.graph import START, StateGraph


def triage(state):
    return state


def escalate(state):
    shutil.rmtree(state["path"])


g = StateGraph(dict)
g.add_node("triage", triage)
g.add_node("escalate", escalate)
g.add_edge(START, "triage")
g.add_edge("triage", "escalate")
app = g.compile()


def handle():
    q = request.json["q"]
    return app.invoke({"path": q})
