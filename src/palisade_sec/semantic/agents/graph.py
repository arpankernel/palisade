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
from palisade_sec.semantic.probe import capabilities_in, harvest_tools
from palisade_sec.semantic.walk import module_calls

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
    """Extract the multi-agent topology. Pure, offline, deterministic.

    Runs a set of framework adapters, each contributing nodes and/or edges:
    the generic kwarg shape (OpenAI Agents SDK-style `Agent(tools=, handoffs=)`),
    LangGraph (`add_node`/`add_edge`), and CrewAI (`Crew(agents=, process=)`).
    """
    caps_by_tool = {t.name: t.capabilities for t in harvest_tools(modules)}
    funcs_by_name = {fn.name: fn for mod in modules for fn in mod.functions}
    graph = AgentGraph()
    pending_edges: list[AgentEdge] = []

    for extract in (_extract_kwarg_agents, _extract_langgraph, _extract_crewai):
        nodes, edges = extract(modules, caps_by_tool, funcs_by_name)
        for node in nodes:
            graph.nodes.setdefault(node.name, node)
        pending_edges.extend(edges)

    # Keep edges whose endpoints are both known agents (precision-first).
    graph.edges = [e for e in pending_edges if e.src in graph.nodes and e.dst in graph.nodes]
    return graph


def _all_calls(modules: list[ir.Module]):
    for mod in modules:
        yield from module_calls(mod)


def _extract_kwarg_agents(
    modules: list[ir.Module], caps_by_tool: dict, funcs_by_name: dict
) -> tuple[list[AgentNode], list[AgentEdge]]:
    """Generic + OpenAI Agents SDK: `x = Agent(name=, tools=[...], handoffs=[...])`.
    Also covers CrewAI agents (`Agent(role=, tools=[...])`), which get their
    edges from the CrewAI adapter."""
    nodes: list[AgentNode] = []
    edges: list[AgentEdge] = []
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
                nodes.append(
                    AgentNode(
                        name=node_id,
                        display=_const_str(call.kwargs.get("name")) or node_id,
                        file=loc.file,
                        line=loc.line,
                        tools=tools,
                        capabilities=caps,
                    )
                )
                for dst in _names_in_collection(call.kwargs.get("handoffs")):
                    edges.append(AgentEdge(src=node_id, dst=dst))
    return nodes, edges


# LangGraph reserved pseudo-nodes that are not agents.
_LG_SPECIAL = {"__start__", "__end__", "START", "END", "start", "end"}


def _extract_langgraph(
    modules: list[ir.Module], caps_by_tool: dict, funcs_by_name: dict
) -> tuple[list[AgentNode], list[AgentEdge]]:
    """LangGraph: `g.add_node("name", fn)` + `g.add_edge("a", "b")`. A node's
    capabilities come from its bound function's body (or a ToolNode's tools).
    Conditional edges are recall, deferred; add_edge is precise."""
    nodes: list[AgentNode] = []
    edges: list[AgentEdge] = []
    for call in _all_calls(modules):
        tail = call.func_path.rsplit(".", 1)[-1]
        if tail == "add_node":
            name = _const_str(call.args[0]) if call.args else _const_str(call.kwargs.get("node"))
            if not name:
                continue
            target = call.args[1] if len(call.args) > 1 else None
            caps = _target_capabilities(target, funcs_by_name, caps_by_tool)
            nodes.append(
                AgentNode(
                    name=name,
                    display=name,
                    file=call.loc.file,
                    line=call.loc.line,
                    tools=[],
                    capabilities=caps,
                )
            )
        elif tail == "add_edge":
            src = _const_str(call.args[0]) if call.args else None
            dst = _const_str(call.args[1]) if len(call.args) > 1 else None
            if src and dst and src not in _LG_SPECIAL and dst not in _LG_SPECIAL:
                edges.append(AgentEdge(src, dst))
    return nodes, edges


def _target_capabilities(target: ir.Expr | None, funcs_by_name: dict, caps_by_tool: dict) -> list:
    """Capabilities of a LangGraph node target: a function (walk its body) or a
    ToolNode wrapping tools."""
    if target is None:
        return []
    if isinstance(target, ir.VarRef):
        fn = funcs_by_name.get(target.base_var or target.path)
        if fn is not None:
            return capabilities_in(fn.body)
        return list(caps_by_tool.get(target.base_var or target.path, []))
    if isinstance(target, ir.Call):
        # ToolNode(tools=[...]) / ToolNode([...])
        tool_names = _names_in_collection(target.kwargs.get("tools"))
        if not tool_names and target.args:
            tool_names = _names_in_collection(target.args[0])
        return sorted({c for t in tool_names for c in caps_by_tool.get(t, [])})
    return []


def _extract_crewai(
    modules: list[ir.Module], caps_by_tool: dict, funcs_by_name: dict
) -> tuple[list[AgentNode], list[AgentEdge]]:
    """CrewAI: `Crew(agents=[a, b, c], process=...)`. The agents are already
    nodes (from the generic Agent adapter); this adds the flow edges. Sequential
    (default) chains a->b->c; hierarchical connects the first agent to the rest.
    A heuristic over the declared wiring, kept conservative."""
    edges: list[AgentEdge] = []
    for call in _all_calls(modules):
        if call.func_path.rsplit(".", 1)[-1] != "Crew":
            continue
        agents = _names_in_collection(call.kwargs.get("agents"))
        if len(agents) < 2:
            continue
        proc = _const_str(call.kwargs.get("process")) or _proc_name(call.kwargs.get("process"))
        if proc and "hierarchical" in proc:
            edges.extend(AgentEdge(agents[0], a) for a in agents[1:])
        else:
            edges.extend(AgentEdge(a, b) for a, b in zip(agents, agents[1:], strict=False))
    return [], edges


def _proc_name(expr: ir.Expr | None) -> str | None:
    if isinstance(expr, ir.VarRef):
        return expr.path or expr.base_var or None
    return None
