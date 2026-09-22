"""AgentGraph: the multi-agent topology, extracted statically from the IR.

A node is an agent assigned to a variable; its `tools` are the tools bound in
its construction (`tools=[...]`), and its `capabilities` are the dangerous
capabilities those tools exercise (reused from the PROBE). An edge is a handoff
declared in the construction (`handoffs=[...]`) - agent A can transfer control
to agent B.

Three framework adapters: the explicit-kwarg shape used by the OpenAI Agents
SDK and similar constructors (`Agent(name=, tools=[...], handoffs=[...])`),
LangGraph (`add_node`/`add_edge`/`add_conditional_edges`), and CrewAI
(`Crew(agents=, process=)`); nothing here guesses beyond what the IR states.

`entry_aliases` resolves a "container" variable - `crew = Crew(agents=[...])`
or `app = graph.compile()` - back to the real node that represents where
running the container actually enters the graph, so PI-AGENT-HANDOFF's
run-site detection (which only recognizes an agent/node variable directly)
still fires when the code calls `crew.kickoff(...)` / `app.invoke(...)`
rather than an individual agent's `.run(...)`.
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
    # container variable -> the graph node that is its logical entry point.
    # `crew = Crew(agents=[a, b])` and `app = graph.compile()` are run through
    # the container, not through any single agent/node variable directly - a
    # run site targeting `crew`/`app` needs to resolve back to a real node to
    # be recognized at all. See PI-AGENT-HANDOFF's _run_site().
    entry_aliases: dict[str, str] = field(default_factory=dict)

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
            "entry_aliases": dict(sorted(self.entry_aliases.items())),
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
    LangGraph (`add_node`/`add_edge`/`add_conditional_edges`), and CrewAI
    (`Crew(agents=, process=)`).
    """
    caps_by_tool = {t.name: t.capabilities for t in harvest_tools(modules)}
    funcs_by_name = {fn.name: fn for mod in modules for fn in mod.functions}
    graph = AgentGraph()
    pending_edges: list[AgentEdge] = []
    pending_aliases: dict[str, str] = {}

    for extract in (_extract_kwarg_agents, _extract_langgraph, _extract_crewai):
        nodes, edges, aliases = extract(modules, caps_by_tool, funcs_by_name)
        for node in nodes:
            graph.nodes.setdefault(node.name, node)
        pending_edges.extend(edges)
        pending_aliases.update(aliases)

    # Keep edges whose endpoints are both known agents (precision-first),
    # deduplicated - a dict-literal path_map's keys and values are both
    # walked by _conditional_targets (the IR does not keep dict keys/values
    # distinct), so a path_map like {"escalate": "escalate"} would otherwise
    # produce the same edge twice. AgentEdge is frozen/hashable, so a set
    # dedups while dict.fromkeys keeps first-seen order.
    valid = (e for e in pending_edges if e.src in graph.nodes and e.dst in graph.nodes)
    graph.edges = list(dict.fromkeys(valid))
    # Keep aliases that resolve to a known node - same precision-first bar.
    graph.entry_aliases = {k: v for k, v in pending_aliases.items() if v in graph.nodes}
    return graph


def _all_calls(modules: list[ir.Module]):
    for mod in modules:
        yield from module_calls(mod)


def _extract_kwarg_agents(
    modules: list[ir.Module], caps_by_tool: dict, funcs_by_name: dict
) -> tuple[list[AgentNode], list[AgentEdge], dict[str, str]]:
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
    return nodes, edges, {}


# LangGraph reserved pseudo-nodes that are not agents. START/END are module
# constants (`from langgraph.graph import START, END`), so a reference to one
# lowers to a VarRef whose alias-resolved `path` ends in "START"/"END" (the
# real constant names), not a Const string - _node_ref() below checks both
# forms. "__start__"/"__end__" are their string-literal equivalents, accepted
# directly as add_node/add_edge string arguments in LangGraph's own API.
_LG_SPECIAL = {"__start__", "__end__", "START", "END"}


def _node_ref(expr: ir.Expr | None) -> str | None:
    """A LangGraph node-id argument: either a literal string (`"triage"`) or
    a reference to the START/END sentinel constant. Returns the resolved
    node name, or the literal special-name string for START/END so callers
    can recognize it via `_LG_SPECIAL`."""
    s = _const_str(expr)
    if s is not None:
        return s
    if isinstance(expr, ir.VarRef):
        tail = (expr.path or expr.base_var or "").rsplit(".", 1)[-1]
        return tail or None
    return None


def _extract_langgraph(
    modules: list[ir.Module], caps_by_tool: dict, funcs_by_name: dict
) -> tuple[list[AgentNode], list[AgentEdge], dict[str, str]]:
    """LangGraph: `g.add_node("name", fn)` + `g.add_edge("a", "b")` +
    `g.add_conditional_edges("a", router, {...})`. A node's capabilities come
    from its bound function's body (or a ToolNode's tools).

    `add_conditional_edges(source, router_fn, path_map)` fans `source` out to
    every node the path_map (or, without one, the router's return values -
    unknowable statically) can route to; conservatively, every value in
    `path_map` becomes an edge from `source`. Recall over precision here is
    deliberate: a router that CAN reach a dangerous node is a real path
    regardless of which branch a given input takes, and LangGraph's routing
    primitive is conditional edges - treating it as fully opaque would make
    the common case invisible (`_extract_langgraph`'s prior "deferred" note).

    `builder.compile()` is tracked as an entry alias to the graph's start
    node (whatever `add_edge(START, ...)` / `add_edge("__start__", ...)` /
    `set_entry_point(...)` named), so `app = g.compile(); app.invoke(...)`
    resolves `app` back to a real node instead of being invisible to the
    run-site detector.
    """
    nodes: list[AgentNode] = []
    edges: list[AgentEdge] = []
    builder_entry: dict[str, str] = {}  # builder var -> its start node
    aliases: dict[str, str] = {}  # compiled-graph var -> start node
    for call in _all_calls(modules):
        tail = call.func_path.rsplit(".", 1)[-1]
        recv = _ref_name(call.receiver) if call.receiver is not None else None
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
            src = _node_ref(call.args[0]) if call.args else None
            dst = _node_ref(call.args[1]) if len(call.args) > 1 else None
            if src and dst and src not in _LG_SPECIAL and dst not in _LG_SPECIAL:
                edges.append(AgentEdge(src, dst))
            elif src in _LG_SPECIAL and dst and dst not in _LG_SPECIAL and recv:
                builder_entry.setdefault(recv, dst)
        elif tail == "set_entry_point":
            # Older/alternate LangGraph API: g.set_entry_point("triage").
            dst = _node_ref(call.args[0]) if call.args else None
            if dst and dst not in _LG_SPECIAL and recv:
                builder_entry.setdefault(recv, dst)
        elif tail == "add_conditional_edges":
            src = _node_ref(call.args[0]) if call.args else None
            if not src or src in _LG_SPECIAL:
                continue
            path_map = call.args[2] if len(call.args) > 2 else call.kwargs.get("path_map")
            for dst in _conditional_targets(path_map):
                if dst not in _LG_SPECIAL:
                    edges.append(AgentEdge(src, dst, kind="conditional_handoff"))
    # Second pass: resolve `x = <builder>.compile()` targets to entry aliases.
    # Needs its own walk because the assignment target lives on the Assign
    # statement, not on the Call the loop above iterates.
    for mod in modules:
        bodies = [fn.body for fn in mod.functions]
        if mod.toplevel is not None:
            bodies.append(mod.toplevel.body)
        for body in bodies:
            for targets, call, _loc in _iter_assign_calls(body):
                if call.func_path.rsplit(".", 1)[-1] != "compile" or not targets:
                    continue
                recv = _ref_name(call.receiver) if call.receiver is not None else None
                entry = builder_entry.get(recv) if recv is not None else None
                if entry:
                    aliases[targets[0]] = entry
    return nodes, edges, aliases


def _conditional_targets(path_map: ir.Expr | None) -> list[str]:
    """Every node id an `add_conditional_edges` path_map can route to. A dict
    literal's values are the destinations (`{"yes": "escalate", "no": END}`);
    a collection (list/tuple of destination names, or no map at all - the
    router's return values are the destinations) is read the same way, best
    effort. No path_map at all (router returns node names directly) yields
    nothing here - that shape is unknowable without executing the router."""
    if path_map is None:
        return []
    out: list[str] = []
    if isinstance(path_map, ir.Collection):
        for item in path_map.items:
            ref = _node_ref(item)
            if ref:
                out.append(ref)
    return out


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
) -> tuple[list[AgentNode], list[AgentEdge], dict[str, str]]:
    """CrewAI: `Crew(agents=[a, b, c], process=...)`. The agents are already
    nodes (from the generic Agent adapter); this adds the flow edges. Sequential
    (default) chains a->b->c; hierarchical connects the first agent to the rest.
    A heuristic over the declared wiring, kept conservative.

    `crew = Crew(agents=[...])` also aliases `crew` to `agents[0]` (the entry
    every chain shape starts from), so `crew.kickoff(...)` resolves to a real
    node - without this, the crew is fully wired but its only run method is
    invisible to the run-site detector, which only recognizes an agent
    variable directly."""
    edges: list[AgentEdge] = []
    aliases: dict[str, str] = {}
    for mod in modules:
        bodies = [fn.body for fn in mod.functions]
        if mod.toplevel is not None:
            bodies.append(mod.toplevel.body)
        for body in bodies:
            for targets, call, _loc in _iter_assign_calls(body):
                if call.func_path.rsplit(".", 1)[-1] != "Crew":
                    continue
                agents = _names_in_collection(call.kwargs.get("agents"))
                if not agents:
                    continue
                if targets:
                    aliases[targets[0]] = agents[0]
                if len(agents) < 2:
                    continue
                proc = _const_str(call.kwargs.get("process")) or _proc_name(
                    call.kwargs.get("process")
                )
                if proc and "hierarchical" in proc:
                    edges.extend(AgentEdge(agents[0], a) for a in agents[1:])
                else:
                    edges.extend(AgentEdge(a, b) for a, b in zip(agents, agents[1:], strict=False))
    return [], edges, aliases


def _proc_name(expr: ir.Expr | None) -> str | None:
    if isinstance(expr, ir.VarRef):
        return expr.path or expr.base_var or None
    return None
