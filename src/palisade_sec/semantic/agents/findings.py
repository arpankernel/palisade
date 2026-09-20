"""PI-AGENT-HANDOFF: untrusted input driving a multi-agent handoff into a
dangerous capability.

The finding fires only on a complete path:

    untrusted source -> an agent is run with that input -> (>=1 handoff) ->
    an agent that holds a dangerous-capability tool

This honors the core contract: no untrusted source means no finding, exactly
like the taint rules. It reuses the AgentGraph (topology + reachability) and the
same source patterns the taint rules declare, so "untrusted" means the same
thing here as everywhere else.

Scope (honest bounds, v1): untrustedness is tracked intra-procedurally - a
source expression at the run site, or a variable assigned from one earlier in
the same function. Route-decorated params (FastAPI) and cross-function flow into
the run site are not yet followed; that is recall, not precision.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from palisade_sec import ir
from palisade_sec.engine import Finding, TracePoint
from palisade_sec.rules import load_rules
from palisade_sec.rules.schema import PatternSpec, match_strict
from palisade_sec.semantic.agents.graph import AgentGraph, _ref_name, build_agent_graph

RULE_ID = "PI-AGENT-HANDOFF"

# Suffixes of calls that run/invoke an agent with an input.
RUN_SUFFIXES = frozenset(
    {"run", "run_sync", "run_streamed", "kickoff", "kickoff_async", "invoke", "ainvoke"}
)
# kwargs that carry the run input.
INPUT_KWARGS = frozenset({"input", "inputs", "message", "messages", "query", "task"})

_ATTACK = (
    "Crafted input to the entry agent steers a handoff to the target agent and "
    "invokes its dangerous tool, so untrusted input reaches a high-impact action "
    "across an agent boundary with no human in the loop."
)
_FIX = (
    "Do not let an externally-driven agent hand off to an agent holding "
    "irreversible or destructive tools without a gate. Constrain the allowed "
    "handoffs, require human approval before high-impact tools run, and scope "
    "each agent's tools to least privilege."
)
_REFS = [
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "MITRE ATLAS: LLM agent tool misuse",
]


@dataclass
class _RunSite:
    target: str  # agent variable the run invokes
    loc: ir.Loc
    input_exprs: list[ir.Expr]


def _source_specs() -> list[PatternSpec]:
    """The taint rules' source patterns, minus decorator sources (route params),
    which need engine-level handling not modelled here yet."""
    specs: list[PatternSpec] = []
    for rule in load_rules(None).rules:
        specs.extend(s for s in rule.sources if s.kind != "decorator")
    return specs


def _matches_source(path: str, specs: list[PatternSpec]) -> bool:
    return bool(path) and any(match_strict(path, p) for s in specs for p in s.patterns)


def _expr_untrusted(expr: ir.Expr | None, specs: list[PatternSpec], tainted: set[str]) -> bool:
    if expr is None:
        return False
    if isinstance(expr, ir.VarRef):
        if expr.base_var in tainted or (expr.path and expr.path in tainted):
            return True
        return _matches_source(expr.path, specs)
    if isinstance(expr, ir.Member):
        return _matches_source(expr.path, specs) or _expr_untrusted(expr.base, specs, tainted)
    if isinstance(expr, ir.Call):
        if _matches_source(expr.func_path, specs):
            return True
        if _expr_untrusted(expr.receiver, specs, tainted):
            return True
        return any(_expr_untrusted(a, specs, tainted) for a in expr.args)
    if isinstance(expr, ir.StrJoin):
        return any(_expr_untrusted(p, specs, tainted) for p in expr.parts)
    if isinstance(expr, (ir.Collection, ir.Unknown)):
        children = expr.items if isinstance(expr, ir.Collection) else expr.children
        return any(_expr_untrusted(c, specs, tainted) for c in children)
    return False


def _walk_assigns(stmts: list[ir.Stmt]):
    for st in stmts:
        if isinstance(st, ir.Assign):
            yield st
        if isinstance(st, ir.IfBranch):
            yield from _walk_assigns(st.body)
            yield from _walk_assigns(st.orelse)
        elif isinstance(st, ir.ForLoop):
            yield from _walk_assigns(st.body)
        elif isinstance(st, ir.WhileLoop):
            yield from _walk_assigns(st.body)
        elif isinstance(st, ir.TryBlock):
            yield from _walk_assigns(st.body)
            for h in st.handlers:
                yield from _walk_assigns(h)
            yield from _walk_assigns(st.finalbody)
        elif isinstance(st, ir.WithBlock):
            yield from _walk_assigns(st.body)


def _tainted_vars(stmts: list[ir.Stmt], specs: list[PatternSpec]) -> set[str]:
    """Forward pass: variables that hold untrusted data in this function."""
    tainted: set[str] = set()
    for a in _walk_assigns(stmts):
        if _expr_untrusted(a.value, specs, tainted):
            tainted.update(a.targets)
    return tainted


def _iter_calls(stmts: list[ir.Stmt]):
    from palisade_sec.semantic.walk import iter_calls

    yield from iter_calls(stmts)


def _run_site(call: ir.Call, graph: AgentGraph) -> _RunSite | None:
    tail = call.func_path.rsplit(".", 1)[-1]
    if tail not in RUN_SUFFIXES:
        return None
    # receiver form: agent.run(x); classmethod form: Runner.run(agent, x)
    recv = _ref_name(call.receiver) if call.receiver is not None else None
    if recv in graph.nodes:
        inputs = list(call.args)
    elif call.args and _ref_name(call.args[0]) in graph.nodes:
        recv = _ref_name(call.args[0])
        inputs = list(call.args[1:])
    else:
        return None
    inputs += [v for k, v in call.kwargs.items() if k in INPUT_KWARGS]
    assert recv is not None
    return _RunSite(target=recv, loc=call.loc, input_exprs=inputs)


def _distance(graph: AgentGraph, start: str, target: str) -> int:
    adj: dict[str, list[str]] = {}
    for e in graph.edges:
        adj.setdefault(e.src, []).append(e.dst)
    q = deque([(start, 0)])
    seen = {start}
    while q:
        cur, d = q.popleft()
        for nxt in adj.get(cur, []):
            if nxt == target:
                return d + 1
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, d + 1))
    return -1


def _confidence(depth: int) -> str:
    if depth <= 1:
        return "HIGH"
    if depth == 2:
        return "MEDIUM"
    return "LOW"


def find_agent_handoff_findings(modules: list[ir.Module]) -> list[Finding]:
    """Deterministic, offline. Emit a PI-AGENT-HANDOFF finding for each
    untrusted-input -> entry agent -> handoff -> dangerous agent path."""
    specs = _source_specs()
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    # Analyze one module at a time: agent variables are module-local, so a
    # cross-module graph would merge distinct agents that happen to share a name
    # (e.g. `triage` in two files) and misattribute findings.
    for mod in modules:
        graph = build_agent_graph([mod])
        if not graph.edges:
            continue
        bodies = [fn.body for fn in mod.functions]
        if mod.toplevel is not None:
            bodies.append(mod.toplevel.body)
        for body in bodies:
            tainted = _tainted_vars(body, specs)
            for call in _iter_calls(body):
                site = _run_site(call, graph)
                if site is None:
                    continue
                if not any(_expr_untrusted(e, specs, tainted) for e in site.input_exprs):
                    continue
                for dst in sorted(graph.reachable_from(site.target)):
                    caps = graph.nodes[dst].capabilities
                    if not caps:
                        continue
                    key = (site.loc.file, site.loc.line, dst)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_build_finding(graph, site, dst, caps))
    return findings


def _build_finding(graph: AgentGraph, site: _RunSite, dst: str, caps: list[str]) -> Finding:
    entry = graph.nodes[site.target]
    danger = graph.nodes[dst]
    depth = _distance(graph, site.target, dst)
    return Finding(
        rule_id=RULE_ID,
        title="Prompt injection reaching a dangerous capability across an agent handoff",
        severity="high",
        confidence=_confidence(depth),
        source=TracePoint(
            file=site.loc.file,
            line=site.loc.line,
            snippet=site.loc.snippet,
            detail=f"untrusted input to agent `{site.target}`",
        ),
        llm=TracePoint(
            file=entry.file,
            line=entry.line,
            snippet=f"agent `{entry.display}`",
            detail=f"handoff chain to `{danger.display}` ({depth} hop(s))",
        ),
        sink=TracePoint(
            file=danger.file,
            line=danger.line,
            snippet=f"agent `{danger.display}` tools: {', '.join(danger.tools)}",
            detail=f"capabilities: {', '.join(caps)}",
        ),
        attack=_ATTACK,
        fix=_FIX,
        references=_REFS,
    )
