"""AgentGraph: the multi-agent topology, extracted statically from the IR.

A node is an agent assigned to a variable; its `tools` are the tools bound in
its construction (`tools=[...]`), and its `capabilities` are the dangerous
capabilities those tools exercise (reused from the PROBE). An edge is a handoff
declared in the construction (`handoffs=[...]`) - agent A can transfer control
to agent B.

v1 recognizes the explicit-kwarg shape used by the OpenAI Agents SDK and
similar constructors (`Agent(name=, tools=[...], handoffs=[...])`). LangGraph
(`add_node`/`add_edge`) and CrewAI (`Crew(agents=, tasks=)`) get their own
adapters in Phase 2; nothing here guesses beyond what the IR states.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from palisade_sec import ir
from palisade_sec.rules.schema import match_strict
from palisade_sec.semantic.probe import harvest_tools

# Agent constructors that carry tools=/handoffs= kwargs. Kept tight for v1.
AGENT_CTORS: tuple[str, ...] = (
    "Agent",
    "*.Agent",
    "Assistant",
    "*.Assistant",
    "*.ConversableAgent",
)


@dataclass
class AgentNode:
    name: str  # the variable it is assigned to (the node id)
    display: str  # the name= kwarg if present, else the variable name
    file: str
    line: int
    tools: list[str] = field(default_factory=list)  # tool names bound in tools=[...]
    capabilities: list[str] = field(default_factory=list)  # union of those tools' caps

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "display": self.display,
            "file": self.file,
            "line": self.line,
            "tools": self.tools,
            "capabilities": self.capabilities,
        }


@dataclass(frozen=True)
class AgentEdge:
    src: str
    dst: str
    kind: str = "handoff"

    def to_dict(self) -> dict:
        return {"src": self.src, "dst": self.dst, "kind": self.kind}


@dataclass
class AgentGraph:
    nodes: dict[str, AgentNode] = field(default_factory=dict)
    edges: list[AgentEdge] = field(default_factory=list)

    def entry_nodes(self) -> list[str]:
        """Nodes with no incoming handoff - the roots an external caller hits."""
        targets = {e.dst for e in self.edges if e.dst in self.nodes}
        return sorted(n for n in self.nodes if n not in targets)

    def reachable_from(self, start: str) -> set[str]:
        """Every node reachable from `start` by following handoff edges."""
        adj: dict[str, list[str]] = {}
        for e in self.edges:
            adj.setdefault(e.src, []).append(e.dst)
        seen: set[str] = set()
        q = deque([start])
        while q:
            cur = q.popleft()
            for nxt in adj.get(cur, []):
                if nxt in self.nodes and nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
        return seen

    def dangerous_reach(self) -> list[dict]:
        """From each entry, which capability-bearing agents are reachable across
        at least one handoff. This is the raw signal Phase 1b turns into a
        finding once tied to an untrusted source."""
        out: list[dict] = []
        for entry in self.entry_nodes():
            for dst in sorted(self.reachable_from(entry)):
                caps = self.nodes[dst].capabilities
                if caps:
                    out.append({"from": entry, "to": dst, "capabilities": caps})
        return out

    def to_dict(self) -> dict:
        return {
            "nodes": [self.nodes[n].to_dict() for n in sorted(self.nodes)],
            "edges": [e.to_dict() for e in self.edges],
            "entry_nodes": self.entry_nodes(),
            "dangerous_reach": self.dangerous_reach(),
        }


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


def _iter_assign_calls(stmts: list[ir.Stmt]):
    """Yield (targets, Call) for every assignment whose value is a call,
    recursing into nested bodies."""
    for st in stmts:
        if isinstance(st, ir.Assign) and isinstance(st.value, ir.Call):
            yield st.targets, st.value, st.loc
        if isinstance(st, ir.IfBranch):
            yield from _iter_assign_calls(st.body)
            yield from _iter_assign_calls(st.orelse)
        elif isinstance(st, ir.ForLoop):
            yield from _iter_assign_calls(st.body)
        elif isinstance(st, ir.WhileLoop):
            yield from _iter_assign_calls(st.body)
        elif isinstance(st, ir.TryBlock):
            yield from _iter_assign_calls(st.body)
            for h in st.handlers:
                yield from _iter_assign_calls(h)
            yield from _iter_assign_calls(st.finalbody)
        elif isinstance(st, ir.WithBlock):
            yield from _iter_assign_calls(st.body)


def _ref_name(expr: ir.Expr) -> str | None:
    """The referenced identifier: a var, or the first arg of a wrapper call
    like `handoff(writer)`."""
    if isinstance(expr, ir.VarRef):
        return expr.base_var or expr.path or None
    if isinstance(expr, ir.Call) and expr.args:
        return _ref_name(expr.args[0])
    if isinstance(expr, ir.Member) and expr.base is not None:
        return _ref_name(expr.base)
    return None


def _names_in_collection(expr: ir.Expr | None) -> list[str]:
    if not isinstance(expr, ir.Collection):
        return []
    out: list[str] = []
    for item in expr.items:
        name = _ref_name(item)
        if name:
            out.append(name)
    return out


def _is_agent_ctor(func_path: str) -> bool:
    return any(match_strict(func_path, p) for p in AGENT_CTORS)


def _const_str(expr: ir.Expr | None) -> str | None:
    return expr.value if isinstance(expr, ir.Const) and isinstance(expr.value, str) else None


def build_agent_graph(modules: list[ir.Module]) -> AgentGraph:
    """Extract the multi-agent topology. Pure, offline, deterministic."""
    caps_by_tool = {t.name: t.capabilities for t in harvest_tools(modules)}
    graph = AgentGraph()
    pending_edges: list[AgentEdge] = []

    for mod in modules:
        bodies = [fn.body for fn in mod.functions]
        if mod.toplevel is not None:
            bodies.append(mod.toplevel.body)
        for body in bodies:
            for targets, call, loc in _iter_assign_calls(body):
                if not targets or not _is_agent_ctor(call.func_path):
                    continue
                node_id = targets[0]
                tools = _names_in_collection(call.kwargs.get("tools"))
                caps = sorted({c for t in tools for c in caps_by_tool.get(t, [])})
                graph.nodes[node_id] = AgentNode(
                    name=node_id,
                    display=_const_str(call.kwargs.get("name")) or node_id,
                    file=loc.file,
                    line=loc.line,
                    tools=tools,
                    capabilities=caps,
                )
                for dst in _names_in_collection(call.kwargs.get("handoffs")):
                    pending_edges.append(AgentEdge(src=node_id, dst=dst))

    # Keep edges whose endpoints are both known agents (precision-first).
    graph.edges = [e for e in pending_edges if e.src in graph.nodes and e.dst in graph.nodes]
    return graph
