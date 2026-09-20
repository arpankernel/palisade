"""PROBE: deterministic harvesting of safety-relevant artifacts from the IR.

The taint engine only ever *used* the source -> LLM -> sink slice of the IR.
The PROBE exposes the rest of the AI-relevant surface so the semantic JUDGE
can reason about it. It is pure, offline, and fully unit-testable - it makes
no network calls and no judgments; it only extracts grounded facts.

First artifact class: **agent tools** (for the excessive-agency check). A tool
is a function a model can decide to invoke. The PROBE finds them by decorator
and records which dangerous *capabilities* their bodies exercise, with the
exact call sites as evidence. Only capability evidence the IR actually
contains is ever reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from palisade_sec import ir
from palisade_sec.rules.schema import match_strict
from palisade_sec.semantic.walk import iter_calls

# Decorators that mark a function as a model-invocable tool, across the common
# Python agent frameworks (LangChain `@tool` / `@agent.tool`, OpenAI Agents
# `@function_tool`, Pydantic-AI `@agent.tool`/`@agent.tool_plain`, CrewAI
# `@tool`). Alias-resolved dotted paths, matched with the strict rule matcher.
TOOL_DECORATORS: tuple[str, ...] = (
    "tool",
    "*.tool",
    "*.tool_plain",
    "function_tool",
    "*.function_tool",
    "*.ai_function",
    "langchain_core.tools.tool",
)

# Capability categories -> dotted call patterns. This is a *cost gate*, not a
# precision gate: a tool touching any of these is worth a judgment; the JUDGE
# decides whether that capability is actually dangerous in context. Patterns
# use the same strict semantics as rules ("*.x" = any path ending in ".x").
CAPABILITIES: dict[str, tuple[str, ...]] = {
    "shell": (
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "child_process.exec",
        "child_process.execSync",
        "child_process.spawn",
    ),
    "code_exec": ("exec", "eval", "compile", "__import__", "importlib.import_module"),
    "file_write": (
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "shutil.rmtree",
        "shutil.move",
        "*.write_text",
        "*.write_bytes",
        "*.unlink",
    ),
    "network": (
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "httpx.get",
        "httpx.post",
        "urllib.request.urlopen",
    ),
    "db_write": ("*.execute", "*.executemany", "*.commit", "*.delete", "*.drop"),
    "payments": ("*.charge", "*.transfer", "*.payout", "stripe.PaymentIntent.create"),
    "email": ("*.sendmail", "*.send_message", "*.send_email", "smtplib.SMTP.sendmail"),
    "cloud": ("boto3.client", "boto3.resource", "*.delete_object", "*.terminate_instances"),
    "secrets": ("os.getenv", "os.environ.get"),
}


@dataclass(frozen=True)
class CapabilityHit:
    """One dangerous call the IR found inside a tool body - the evidence a
    judgment is grounded on."""

    category: str
    func_path: str
    file: str
    line: int
    snippet: str


@dataclass
class ToolArtifact:
    """A model-invocable tool and the capabilities its body exercises."""

    name: str
    qualname: str
    file: str
    line: int
    decorator: str  # which decorator marked it a tool
    docstring: str = ""  # its stated purpose, if any
    capability_hits: list[CapabilityHit] = field(default_factory=list)

    @property
    def capabilities(self) -> list[str]:
        return sorted({h.category for h in self.capability_hits})


def _match_category(func_path: str) -> str | None:
    for category, patterns in CAPABILITIES.items():
        for pat in patterns:
            if match_strict(func_path, pat):
                return category
    return None


def capabilities_in(stmts: list[ir.Stmt]) -> list[str]:
    """The dangerous capability categories a statement body exercises. Used for
    agent nodes that are plain functions (e.g. LangGraph nodes), not @tool
    functions."""
    cats: set[str] = set()
    for call in iter_calls(stmts):
        cat = _match_category(call.func_path)
        if cat is not None:
            cats.add(cat)
    return sorted(cats)


def _docstring(fn: ir.FuncDef) -> str:
    """First bare string expression in the body, if the frontend kept it."""
    for st in fn.body:
        if isinstance(st, ir.ExprStmt) and isinstance(st.value, ir.Const):
            if isinstance(st.value.value, str):
                return st.value.value.strip().splitlines()[0][:200] if st.value.value else ""
        break
    return ""


def _tool_decorator(fn: ir.FuncDef) -> str | None:
    for dec in fn.decorators:
        for pat in TOOL_DECORATORS:
            if match_strict(dec, pat):
                return dec
    return None


def harvest_tools(modules: list[ir.Module]) -> list[ToolArtifact]:
    """Find every model-invocable tool and the capabilities it exercises.

    Returns all tools (capabilities may be empty); the audit layer applies the
    cost gate of only judging tools that actually touch a capability.
    """
    artifacts: list[ToolArtifact] = []
    for mod in modules:
        for fn in mod.functions:
            dec = _tool_decorator(fn)
            if dec is None:
                continue
            hits: list[CapabilityHit] = []
            seen: set[tuple[str, int]] = set()
            for call in iter_calls(fn.body):
                cat = _match_category(call.func_path)
                if cat is None:
                    continue
                key = (call.func_path, call.loc.line)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    CapabilityHit(
                        category=cat,
                        func_path=call.func_path,
                        file=call.loc.file,
                        line=call.loc.line,
                        snippet=call.loc.snippet,
                    )
                )
            artifacts.append(
                ToolArtifact(
                    name=fn.name,
                    qualname=fn.qualname,
                    file=fn.loc.file,
                    line=fn.loc.line,
                    decorator=dec,
                    docstring=_docstring(fn),
                    capability_hits=hits,
                )
            )
    return artifacts
