"""The AI System Map (the SEE pillar): a deterministic, OFFLINE inventory of a
codebase's entire AI surface.

You cannot secure what you cannot see. Before any judgment, an AI safety
engineer inventories every place the system touches a model: LLM call sites,
prompts, tools, agents/chains, retrieval, and dangerous config flags. This map
is pure static analysis over the IR - no network, no key, no TypeSafe. It is
the foundation every judged check (excessive agency, secrets-in-prompt, ...)
builds on, and it doubles as a standalone `palisade map` for the free tier.

LLM call sites are recognized using the SAME `llm_signatures` the taint rules
already declare - the map knows what a model call is because the rules do.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from palisade_sec import ir
from palisade_sec.rules import load_rules
from palisade_sec.rules.schema import PatternSpec, match_any_strict, match_strict
from palisade_sec.semantic.agents import AgentGraph, build_agent_graph
from palisade_sec.semantic.probe import harvest_tools
from palisade_sec.semantic.walk import module_calls

# Kinds of AI-surface artifact the map inventories.
KIND_LLM_CALL = "llm_call"
KIND_PROMPT = "prompt"
KIND_TOOL = "tool"
KIND_AGENT = "agent"
KIND_RETRIEVAL = "retrieval"
KIND_CONFIG_FLAG = "config_flag"

# Agent / chain constructors across common frameworks (dotted, alias-resolved).
AGENT_CONSTRUCTORS: tuple[str, ...] = (
    "initialize_agent",
    "*.initialize_agent",
    "*.AgentExecutor",
    "*.create_react_agent",
    "*.create_openai_functions_agent",
    "*.create_tool_calling_agent",
    "*.LLMChain",
    "*.Agent",
    "*.Crew",
)

# Retrieval / RAG call sites.
RETRIEVAL_CALLS: tuple[str, ...] = (
    "*.similarity_search",
    "*.max_marginal_relevance_search",
    "*.as_retriever",
    "*.get_relevant_documents",
    "*.aget_relevant_documents",
)

# kwargs that carry a prompt / instructions into a model call.
PROMPT_KWARGS: frozenset[str] = frozenset(
    {"prompt", "messages", "system", "system_prompt", "instructions", "input", "template"}
)

# kwargs whose truthy literal value is a known-dangerous switch.
DANGEROUS_FLAGS: frozenset[str] = frozenset(
    {"allow_dangerous_code", "allow_dangerous_requests", "allow_dangerous_tools"}
)

# kwargs commonly holding a model id, in priority order.
MODEL_KWARGS: tuple[str, ...] = ("model", "model_name", "deployment_name", "azure_deployment")

# Coarse provider inference from the call path (display only).
_PROVIDER_HINTS: tuple[tuple[str, str], ...] = (
    ("anthropic", "anthropic"),
    ("chatanthropic", "anthropic"),
    ("openai", "openai"),
    ("chatopenai", "openai"),
    ("completions.create", "openai"),
    ("gemini", "google"),
    ("generativemodel", "google"),
    ("bedrock", "aws"),
    ("cohere", "cohere"),
    ("ollama", "ollama"),
    ("litellm", "litellm"),
)


@dataclass(frozen=True)
class Artifact:
    kind: str
    name: str  # func path / tool name
    file: str
    line: int
    snippet: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "detail": self.detail,
        }


@dataclass
class AISystemMap:
    llm_calls: list[Artifact] = field(default_factory=list)
    prompts: list[Artifact] = field(default_factory=list)
    tools: list[Artifact] = field(default_factory=list)
    agents: list[Artifact] = field(default_factory=list)
    retrieval: list[Artifact] = field(default_factory=list)
    config_flags: list[Artifact] = field(default_factory=list)
    agent_graph: AgentGraph = field(default_factory=AgentGraph)

    def all(self) -> list[Artifact]:
        return (
            self.llm_calls
            + self.prompts
            + self.tools
            + self.agents
            + self.retrieval
            + self.config_flags
        )

    def summary(self) -> dict:
        return {
            "llm_calls": len(self.llm_calls),
            "prompts": len(self.prompts),
            "prompts_dynamic": sum(1 for p in self.prompts if p.detail.get("dynamic")),
            "tools": len(self.tools),
            "tools_with_capabilities": sum(1 for t in self.tools if t.detail.get("capabilities")),
            "agents": len(self.agents),
            "agent_handoffs": len(self.agent_graph.edges),
            "retrieval": len(self.retrieval),
            "config_flags": len(self.config_flags),
        }

    def to_dict(self, files_scanned: int) -> dict:
        return {
            "tool": "palisade-sec map",
            "files_scanned": files_scanned,
            "summary": self.summary(),
            "artifacts": [a.to_dict() for a in self.all()],
            "agent_graph": self.agent_graph.to_dict(),
        }


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


def _llm_sig_specs() -> list[PatternSpec]:
    """The LLM call signatures the taint rules already declare."""
    specs: list[PatternSpec] = []
    for rule in load_rules(None).rules:
        specs.extend(rule.llm_signatures)
    return specs


def _const_str(expr: ir.Expr | None) -> str | None:
    return expr.value if isinstance(expr, ir.Const) and isinstance(expr.value, str) else None


def _is_static(expr: ir.Expr | None) -> bool:
    """A prompt is static only if it is a bare literal; anything built or
    interpolated (StrJoin / Collection / Call / VarRef) is dynamic."""
    return isinstance(expr, ir.Const)


def _provider(func_path: str) -> str:
    low = func_path.lower()
    for hint, name in _PROVIDER_HINTS:
        if hint in low:
            return name
    return "unknown"


def _model_id(call: ir.Call) -> str | None:
    for key in MODEL_KWARGS:
        v = _const_str(call.kwargs.get(key))
        if v:
            return v
    return None


def _match(func_path: str, patterns: tuple[str, ...]) -> bool:
    return any(match_strict(func_path, p) for p in patterns)


def build_map(modules: list[ir.Module]) -> AISystemMap:
    """Inventory the whole AI surface. Deterministic and offline."""
    m = AISystemMap()
    llm_specs = _llm_sig_specs()

    for mod in modules:
        for call in module_calls(mod):
            fp = call.func_path
            if not fp:
                continue
            loc = call.loc

            if match_any_strict(fp, llm_specs) is not None:
                m.llm_calls.append(
                    Artifact(
                        kind=KIND_LLM_CALL,
                        name=fp,
                        file=loc.file,
                        line=loc.line,
                        snippet=loc.snippet,
                        detail={"provider": _provider(fp), "model": _model_id(call)},
                    )
                )
                _collect_prompts(m, call)

            if _match(fp, AGENT_CONSTRUCTORS):
                m.agents.append(Artifact(KIND_AGENT, fp, loc.file, loc.line, loc.snippet, {}))

            if _match(fp, RETRIEVAL_CALLS):
                m.retrieval.append(
                    Artifact(KIND_RETRIEVAL, fp, loc.file, loc.line, loc.snippet, {})
                )

            for key, val in call.kwargs.items():
                if key in DANGEROUS_FLAGS and isinstance(val, ir.Const) and val.value is True:
                    m.config_flags.append(
                        Artifact(
                            kind=KIND_CONFIG_FLAG,
                            name=f"{fp}({key}=True)",
                            file=loc.file,
                            line=loc.line,
                            snippet=loc.snippet,
                            detail={"flag": key, "on_call": fp},
                        )
                    )

    for tool in harvest_tools(modules):
        m.tools.append(
            Artifact(
                kind=KIND_TOOL,
                name=tool.name,
                file=tool.file,
                line=tool.line,
                snippet="",
                detail={
                    "decorator": tool.decorator,
                    "capabilities": tool.capabilities,
                    "purpose": tool.docstring,
                },
            )
        )
    m.agent_graph = build_agent_graph(modules)
    return m


def _collect_prompts(m: AISystemMap, call: ir.Call) -> None:
    """Record prompt-bearing arguments of an LLM call, static vs dynamic."""
    for key, val in call.kwargs.items():
        if key not in PROMPT_KWARGS:
            continue
        dynamic = not _is_static(val)
        m.prompts.append(
            Artifact(
                kind=KIND_PROMPT,
                name=f"{call.func_path}({key}=)",
                file=call.loc.file,
                line=call.loc.line,
                snippet=call.loc.snippet,
                detail={"arg": key, "dynamic": dynamic},
            )
        )


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def to_json(m: AISystemMap, files_scanned: int) -> str:
    return json.dumps(m.to_dict(files_scanned), indent=2)


def print_map(console, m: AISystemMap, files_scanned: int) -> None:
    from rich.table import Table

    s = m.summary()
    total = len(m.all())
    if total == 0:
        console.print(
            f"[dim]No AI surface found in {files_scanned} file(s).[/dim] "
            "(no LLM calls, tools, agents, or retrieval)"
        )
        return

    console.print(f"[bold]AI System Map[/bold]  ({files_scanned} file(s) scanned)\n")
    console.print(
        f"  LLM calls: {s['llm_calls']}   prompts: {s['prompts']} "
        f"({s['prompts_dynamic']} dynamic)   tools: {s['tools']} "
        f"({s['tools_with_capabilities']} with capabilities)\n"
        f"  agents/chains: {s['agents']}   retrieval: {s['retrieval']}   "
        f"[{'red' if s['config_flags'] else 'green'}]dangerous flags: "
        f"{s['config_flags']}[/]\n"
    )

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("kind", no_wrap=True)
    table.add_column("what", overflow="fold")
    table.add_column("where", no_wrap=True)
    for a in m.all():
        table.add_row(a.kind, _describe(a), f"{a.file}:{a.line}")
    console.print(table)

    _print_agent_graph(console, m.agent_graph)


def _print_agent_graph(console, g: AgentGraph) -> None:
    from rich.markup import escape

    if not g.edges:
        return
    console.print(
        f"\n[bold]Agent handoffs[/bold]  ({len(g.nodes)} agent(s), {len(g.edges)} handoff(s))"
    )
    for e in g.edges:
        caps = g.nodes[e.dst].capabilities if e.dst in g.nodes else []
        cap_txt = f"  [red](can: {escape(', '.join(caps))})[/red]" if caps else ""
        console.print(f"  {escape(e.src)} → {escape(e.dst)}{cap_txt}")
    reach = g.dangerous_reach()
    if reach:
        console.print(
            "  [dim]entry agents can reach a dangerous capability across a handoff: "
            + escape(", ".join(f"{r['from']}→{r['to']}" for r in reach))
            + "[/dim]"
        )


def _describe(a: Artifact) -> str:
    d = a.detail
    if a.kind == KIND_LLM_CALL:
        model = d.get("model") or "?"
        return f"{a.name}  ({d.get('provider')}, model={model})"
    if a.kind == KIND_PROMPT:
        return f"{a.name}  {'dynamic' if d.get('dynamic') else 'static'}"
    if a.kind == KIND_TOOL:
        caps = ", ".join(d.get("capabilities") or []) or "no capabilities"
        return f"{a.name}  ({caps})"
    if a.kind == KIND_CONFIG_FLAG:
        return f"{a.name}  DANGEROUS"
    return a.name
