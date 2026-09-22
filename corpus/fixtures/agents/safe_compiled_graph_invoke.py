"""Compiled LangGraph .invoke() with a constant input, not untrusted.
MUST STAY SILENT."""

import shutil

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
    return app.invoke({"path": "/tmp/fixed"})
