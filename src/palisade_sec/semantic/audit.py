"""AUDIT: orchestrate PROBE -> JUDGE -> policy DECISION for the semantic tier.

This is the `palisade-sec audit` brain. It is deliberately thin: harvest
grounded artifacts, ask a JudgeBackend, route by policy. Routing mirrors the
guardrails cookbook (pass / review / block via dual thresholds plus a severity
override). A best-effort/unverified backend can never emit a BLOCK on judgment
alone; such a decision is downgraded to REVIEW.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from rich.markup import escape

from palisade_sec import ir
from palisade_sec.judge.base import JudgeBackend
from palisade_sec.semantic.judge import (
    Judgment,
    excessive_agency_questions,
    excessive_agency_state,
    interpret,
)
from palisade_sec.semantic.policy import CheckPolicy, SemanticPolicy, default_policy
from palisade_sec.semantic.probe import ToolArtifact, harvest_tools

Decision = str  # "pass" | "review" | "block"


@dataclass
class SemanticFinding:
    check: str
    decision: Decision
    tool_name: str
    file: str
    line: int
    capabilities: list[str]
    irreversible: float
    gated: float
    harm: int
    evidence: list[str] = field(default_factory=list)
    rationale: str = ""
    backend: str = ""
    verified: bool = True

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "decision": self.decision,
            "tool": self.tool_name,
            "file": self.file,
            "line": self.line,
            "capabilities": self.capabilities,
            "judgment": {
                "irreversible": round(self.irreversible, 3),
                "gated": round(self.gated, 3),
                "harm": self.harm,
            },
            "evidence": self.evidence,
            "rationale": self.rationale,
            "backend": self.backend,
            "verified": self.verified,
        }


def decide(policy: CheckPolicy, j: Judgment, verified: bool = True) -> tuple[Decision, str]:
    """Route a judgment to pass / review / block under a check policy.

    An unverified backend never BLOCKs on judgment alone: a would-be block is
    downgraded to review and the reason is recorded."""
    decision, rationale = _route(policy, j)
    if decision == "block" and not verified:
        return "review", rationale + " [downgraded from block: unverified backend]"
    return decision, rationale


def _route(policy: CheckPolicy, j: Judgment) -> tuple[Decision, str]:
    ungated = j.gated < policy.gate_threshold
    if not ungated:
        return "pass", "tool gates the action behind confirmation/approval"
    if j.irreversible >= policy.action_threshold:
        if j.harm >= policy.severity_block:
            return (
                "block",
                f"ungated irreversible action (p={j.irreversible:.2f}) with harm {j.harm}",
            )
        return "review", f"ungated irreversible action (p={j.irreversible:.2f}), harm {j.harm}"
    if j.irreversible >= policy.review_threshold:
        return "review", f"possible ungated irreversible action (p={j.irreversible:.2f})"
    return "pass", "no meaningful irreversible capability"


def audit_excessive_agency(
    modules: list[ir.Module],
    backend: JudgeBackend,
    policy: SemanticPolicy | None = None,
) -> list[SemanticFinding]:
    """Run the excessive-agency check across a project's IR."""
    pol = policy or default_policy()
    check_pol = pol.for_check("excessive_agency")
    questions = excessive_agency_questions(check_pol)
    findings: list[SemanticFinding] = []
    for tool in _judgeable_tools(harvest_tools(modules)):
        result = backend.ask(excessive_agency_state(tool), questions)
        j = interpret(result)
        decision, rationale = decide(check_pol, j, verified=result.verified)
        findings.append(
            SemanticFinding(
                check="excessive_agency",
                decision=decision,
                tool_name=tool.name,
                file=tool.file,
                line=tool.line,
                capabilities=tool.capabilities,
                irreversible=j.irreversible,
                gated=j.gated,
                harm=j.harm,
                evidence=[f"{h.func_path}  ({h.file}:{h.line})" for h in tool.capability_hits],
                rationale=rationale,
                backend=result.backend,
                verified=result.verified,
            )
        )
    return findings


def _judgeable_tools(tools: list[ToolArtifact]) -> list[ToolArtifact]:
    """Cost gate: only spend a judgment call on tools that touch a capability.
    A tool that does pure computation cannot have excessive agency."""
    return [t for t in tools if t.capability_hits]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_DECISION_STYLE = {"block": "bold red", "review": "yellow", "pass": "green"}


def to_json(findings: list[SemanticFinding], tools_seen: int, files_scanned: int) -> str:
    return json.dumps(
        {
            "tool": "palisade-sec audit",
            "check": "excessive_agency",
            "schema_version": 1,
            "files_scanned": files_scanned,
            "tools_judged": len(findings),
            "tools_seen": tools_seen,
            "unverified_backend": any(not f.verified for f in findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def print_findings(console, findings: list[SemanticFinding], tools_seen: int, files_scanned: int):
    from rich.panel import Panel

    if not findings:
        console.print(
            f"[green]No agent tools with dangerous capabilities to judge.[/green] "
            f"({files_scanned} file(s), {tools_seen} tool(s) seen)"
        )
        return
    if any(not f.verified for f in findings):
        console.print(
            "[yellow]note:[/yellow] answers are best-effort from an unverified "
            "backend; blocks are downgraded to review.\n"
        )
    for f in sorted(findings, key=lambda x: (x.decision != "block", x.decision != "review")):
        style = _DECISION_STYLE.get(f.decision, "white")
        where = f"{escape(f.file)}:{f.line}"
        head = f"[{style}]{f.decision.upper()}[/{style}]  {escape(f.tool_name)}  ({where})"
        body = (
            f"capabilities: {escape(', '.join(f.capabilities))}\n"
            f"irreversible={f.irreversible:.2f}  gated={f.gated:.2f}  harm={f.harm}/3\n"
            f"[dim]{escape(f.rationale)}[/dim]\n"
            + "\n".join(f"  ↳ {escape(e)}" for e in f.evidence)
        )
        console.print(Panel(body, title=head, title_align="left", border_style=style))
    blocks = sum(1 for f in findings if f.decision == "block")
    reviews = sum(1 for f in findings if f.decision == "review")
    console.print(
        f"\n{blocks} block · {reviews} review · "
        f"{len(findings) - blocks - reviews} pass  "
        f"({files_scanned} file(s), {len(findings)}/{tools_seen} tool(s) judged)"
    )


def run_audit(
    target: Path,
    backend: JudgeBackend,
    config_file: str | None = None,
    policy: SemanticPolicy | None = None,
) -> tuple[list[SemanticFinding], int, int]:
    """Full path: lower project -> audit. Returns (findings, tools_seen, files)."""
    from palisade_sec.scanner import lower_project

    low = lower_project(target, config_file)
    all_tools = harvest_tools(low.modules)
    findings = audit_excessive_agency(low.modules, backend, policy)
    return findings, len(all_tools), low.files_scanned
