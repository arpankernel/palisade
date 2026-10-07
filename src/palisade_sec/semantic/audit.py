"""AUDIT: run the semantic checks over grounded artifacts, route by policy.

Two checks today, both grounded in a verified static fact:
- excessive_agency: over agent tools the PROBE found.
- taint_exploitability: over source -> LLM -> sink findings the engine proved.

Routing mirrors the guardrails cookbook (pass / review / block via dual
thresholds plus a severity override). A best-effort/unverified backend never
emits a BLOCK on judgment alone; such a decision is downgraded to REVIEW. Every
finding carries a normalized likelihood and impact so `review` can compose one
risk model over all of them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from rich.markup import escape

from palisade_sec import ir
from palisade_sec.engine import Finding
from palisade_sec.judge.base import JudgeBackend
from palisade_sec.judge.guard import UnredactableStateError
from palisade_sec.semantic.exploitability import (
    ExploitJudgment,
    exploitability_questions,
    exploitability_state,
    interpret_exploitability,
)
from palisade_sec.semantic.judge import (
    Judgment,
    excessive_agency_questions,
    excessive_agency_state,
    interpret,
)
from palisade_sec.semantic.policy import (
    CheckPolicy,
    SemanticPolicy,
    default_policy,
    load_policy,
)
from palisade_sec.semantic.probe import ToolArtifact, harvest_tools
from palisade_sec.semantic.risk import static_impact, static_likelihood

Decision = str  # "unjudged" | "pass" | "review" | "block"

# A finding the judgment layer refused to send, because redaction could not
# prove the evidence was free of secrets. It is a coverage gap, not a verdict:
# it never blocks CI, and it is never counted as a pass. Reporting it loudly
# is the whole point, since the alternative is a quietly shorter audit.
UNJUDGED: Decision = "unjudged"


@dataclass
class SemanticFinding:
    check: str  # "excessive_agency" | "taint_exploitability"
    decision: Decision
    title: str
    file: str
    line: int
    likelihood: float  # 0..1
    impact: float  # 0..1
    verified: bool
    backend: str
    evidence: list[str] = field(default_factory=list)
    rationale: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "decision": self.decision,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "likelihood": round(self.likelihood, 3),
            "impact": round(self.impact, 3),
            "verified": self.verified,
            "backend": self.backend,
            "evidence": self.evidence,
            "rationale": self.rationale,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# excessive agency
# --------------------------------------------------------------------------


def decide(policy: CheckPolicy, j: Judgment, verified: bool = True) -> tuple[Decision, str]:
    """Route an excessive-agency judgment. An unverified backend never BLOCKs."""
    decision, rationale = _route_agency(policy, j)
    if decision == "block" and not verified:
        return "review", rationale + " [downgraded from block: unverified backend]"
    return decision, rationale


def _route_agency(policy: CheckPolicy, j: Judgment) -> tuple[Decision, str]:
    if j.gated >= policy.gate_threshold:
        return "pass", "tool gates the action behind confirmation/approval"
    if j.irreversible >= policy.action_threshold:
        if j.harm >= policy.severity_block:
            return "block", f"ungated irreversible action (p={j.irreversible:.2f}), harm {j.harm}"
        return "review", f"ungated irreversible action (p={j.irreversible:.2f}), harm {j.harm}"
    if j.irreversible >= policy.review_threshold:
        return "review", f"possible ungated irreversible action (p={j.irreversible:.2f})"
    return "pass", "no meaningful irreversible capability"


def audit_excessive_agency(
    modules: list[ir.Module],
    backend: JudgeBackend,
    policy: SemanticPolicy | None = None,
) -> list[SemanticFinding]:
    pol = (policy or default_policy()).for_check("excessive_agency")
    questions = excessive_agency_questions(pol)
    findings: list[SemanticFinding] = []
    for tool in _judgeable_tools(harvest_tools(modules)):
        try:
            result = backend.ask(excessive_agency_state(tool), questions)
        except UnredactableStateError as exc:
            findings.append(_unjudged_tool(tool, exc))
            continue
        j = interpret(result)
        decision, rationale = decide(pol, j, verified=result.verified)
        likelihood = j.irreversible * (1.0 if j.gated < pol.gate_threshold else 0.25)
        findings.append(
            SemanticFinding(
                check="excessive_agency",
                decision=decision,
                title=tool.name,
                file=tool.file,
                line=tool.line,
                likelihood=round(likelihood, 3),
                impact=round(j.harm / 3, 3),
                verified=result.verified,
                backend=result.backend,
                evidence=[f"{h.func_path}  ({h.file}:{h.line})" for h in tool.capability_hits],
                rationale=rationale,
                detail={"capabilities": tool.capabilities, "harm": j.harm},
            )
        )
    return findings


def _unjudged_tool(tool: ToolArtifact, exc: UnredactableStateError) -> SemanticFinding:
    """A tool whose capability evidence never left the machine. Locations
    only: the snippets are what could not be cleared."""
    return SemanticFinding(
        check="excessive_agency",
        decision=UNJUDGED,
        title=f"{tool.name} (unjudged)",
        file=tool.file,
        line=tool.line,
        likelihood=0.0,
        impact=0.0,
        verified=False,
        backend="none",
        evidence=[f"{h.file}:{h.line}" for h in tool.capability_hits],
        rationale=(
            "not sent to the judgment endpoint: redaction could not clear the "
            "evidence of secrets. This tool was not judged."
        ),
        detail={
            "capabilities": tool.capabilities,
            "unjudged_reasons": list(exc.reasons),
        },
    )


def _judgeable_tools(tools: list[ToolArtifact]) -> list[ToolArtifact]:
    return [t for t in tools if t.capability_hits]


# --------------------------------------------------------------------------
# taint exploitability
# --------------------------------------------------------------------------


def decide_exploit(
    policy: CheckPolicy, j: ExploitJudgment, verified: bool = True
) -> tuple[Decision, str]:
    decision, rationale = _route_exploit(policy, j)
    if decision == "block" and not verified:
        return "review", rationale + " [downgraded from block: unverified backend]"
    return decision, rationale


def _route_exploit(policy: CheckPolicy, j: ExploitJudgment) -> tuple[Decision, str]:
    if j.exploitable >= policy.action_threshold:
        if j.severity >= policy.severity_block:
            return "block", f"exploitable path (p={j.exploitable:.2f}), impact {j.severity}"
        return "review", f"exploitable path (p={j.exploitable:.2f}), impact {j.severity}"
    if j.exploitable >= policy.review_threshold:
        return "review", f"possibly exploitable path (p={j.exploitable:.2f})"
    return "pass", "path judged not realistically exploitable"


def audit_taint_exploitability(
    findings: list[Finding],
    backend: JudgeBackend,
    policy: SemanticPolicy | None = None,
) -> list[SemanticFinding]:
    pol = (policy or default_policy()).for_check("taint_exploitability")
    questions = exploitability_questions()
    out: list[SemanticFinding] = []
    for f in findings:
        try:
            result = backend.ask(exploitability_state(f), questions)
        except UnredactableStateError as exc:
            out.append(_unjudged_taint(f, exc))
            continue
        j = interpret_exploitability(result)
        decision, rationale = decide_exploit(pol, j, verified=result.verified)
        likelihood, impact = _honest_li(f, j, result.verified)
        sink_name = f.sink.file.rsplit("/", 1)[-1]
        out.append(
            SemanticFinding(
                check="taint_exploitability",
                decision=decision,
                title=f"{f.rule_id} -> {sink_name}:{f.sink.line}",
                file=f.sink.file,
                line=f.sink.line,
                likelihood=round(likelihood, 3),
                impact=round(impact, 3),
                verified=result.verified,
                backend=result.backend,
                evidence=[
                    f"source: {f.source.snippet} ({f.source.file}:{f.source.line})",
                    f"llm:    {f.llm.snippet} ({f.llm.file}:{f.llm.line})",
                    f"sink:   {f.sink.snippet} ({f.sink.file}:{f.sink.line})",
                ],
                rationale=rationale,
                detail={
                    "fingerprint": f.fingerprint,
                    "rule_id": f.rule_id,
                    "exploitable": round(j.exploitable, 3),
                    "impact_level": j.severity,
                },
            )
        )
    return out


def _unjudged_taint(f: Finding, exc: UnredactableStateError) -> SemanticFinding:
    """A taint finding whose evidence never left the machine.

    The static risk basis is kept, so the finding still carries weight in the
    report; what is missing is the judgment that would have refined it. No
    snippet goes into `evidence` here: the reason this path was taken is that
    a snippet could not be cleared, and the reasons on the exception name
    types and paths only.
    """
    sink_name = f.sink.file.rsplit("/", 1)[-1]
    return SemanticFinding(
        check="taint_exploitability",
        decision=UNJUDGED,
        title=f"{f.rule_id} -> {sink_name}:{f.sink.line} (unjudged)",
        file=f.sink.file,
        line=f.sink.line,
        likelihood=round(static_likelihood(f.confidence, f.risky), 3),
        impact=round(static_impact(f.severity), 3),
        verified=False,
        backend="none",
        evidence=[f"{f.source.file}:{f.source.line} -> {f.sink.file}:{f.sink.line}"],
        rationale=(
            "not sent to the judgment endpoint: redaction could not clear the "
            "evidence of secrets. Static finding stands; judgment is missing."
        ),
        detail={
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "unjudged_reasons": list(exc.reasons),
        },
    )


def _honest_li(f: Finding, j: ExploitJudgment, verified: bool) -> tuple[float, float]:
    """Risk basis for a taint finding. A verified backend refines it (up or
    down). An unverified backend does NOT move it in either direction: it can
    neither inflate a finding nor be trusted to deflate a verified path, so the
    deterministic static risk stands and the judgment is advisory only."""
    if verified:
        return j.exploitable, j.severity / 3
    return static_likelihood(f.confidence, f.risky), static_impact(f.severity)


# --------------------------------------------------------------------------
# combined audit + rendering
# --------------------------------------------------------------------------


@dataclass
class AuditReport:
    findings: list[SemanticFinding]
    tools_seen: int
    files_scanned: int
    # (warnings, notes, skipped) from lowering the project.
    diagnostics: tuple[list[str], list[str], list[str]] = field(
        default_factory=lambda: ([], [], [])
    )


def run_audit(
    target: Path,
    backend: JudgeBackend,
    config_file: str | None = None,
    policy: SemanticPolicy | None = None,
    policy_file: str | None = None,
) -> AuditReport:
    """Run both semantic checks. Lowers the project and runs the taint engine
    once (via run_scan) so exploitability judges the real findings.

    An explicit `policy` wins (callers and tests). Otherwise the policy is
    loaded from `policy_file`, else the scanned tree, else the defaults; its
    warnings join the report's diagnostics so a policy that was skipped is
    never skipped silently.
    """
    from palisade_sec.scanner import lower_project, run_scan

    scan = run_scan(target, config_file=config_file)
    low = lower_project(target, config_file)
    policy_warnings: list[str] = []
    if policy is None:
        root = target if target.is_dir() else target.parent
        policy, policy_warnings = load_policy(root, policy_file)
    findings = audit_excessive_agency(low.modules, backend, policy)
    findings += audit_taint_exploitability(scan.findings, backend, policy)
    tools_seen = len(harvest_tools(low.modules))
    return AuditReport(
        findings=findings,
        tools_seen=tools_seen,
        files_scanned=low.files_scanned,
        diagnostics=(
            [*low.warnings, *policy_warnings],
            list(low.notes),
            list(low.skipped),
        ),
    )


_DECISION_STYLE = {
    UNJUDGED: "bold magenta",
    "block": "bold red",
    "review": "yellow",
    "pass": "green",
}


def to_json(report: AuditReport) -> str:
    return json.dumps(
        {
            "tool": "palisade-sec audit",
            "schema_version": 1,
            "files_scanned": report.files_scanned,
            "tools_seen": report.tools_seen,
            "checks_run": sorted({f.check for f in report.findings}),
            "unverified_backend": any(
                not f.verified and f.decision != UNJUDGED for f in report.findings
            ),
            # A consumer that reads only `findings` would see an unjudged
            # entry as one more row. These two keys make the coverage gap
            # legible without parsing decisions.
            "unjudged": sum(1 for f in report.findings if f.decision == UNJUDGED),
            "complete": not any(f.decision == UNJUDGED for f in report.findings),
            "findings": [f.to_dict() for f in report.findings],
        },
        indent=2,
    )


def print_findings(console, report: AuditReport) -> None:
    from rich.panel import Panel

    findings = report.findings
    if not findings:
        console.print(
            f"[green]Nothing to judge.[/green] "
            f"({report.files_scanned} file(s); no dangerous tools and no taint paths)"
        )
        return
    # An unjudged finding has no answer at all, so it is not evidence of an
    # unverified backend. Judging it as one would print the wrong caveat.
    if any(not f.verified and f.decision != UNJUDGED for f in findings):
        console.print(
            "[yellow]note:[/yellow] answers are best-effort from an unverified "
            "backend; blocks are downgraded to review.\n"
        )
    unjudged = sum(1 for f in findings if f.decision == UNJUDGED)
    if unjudged:
        console.print(
            f"[bold magenta]note:[/bold magenta] {unjudged} finding(s) were not sent "
            "to the judgment endpoint because redaction could not clear the evidence "
            "of secrets. This audit is incomplete by that much.\n"
        )
    order = {UNJUDGED: 0, "block": 1, "review": 2, "pass": 3}
    for f in sorted(findings, key=lambda x: (order.get(x.decision, 4), -x.likelihood * x.impact)):
        style = _DECISION_STYLE.get(f.decision, "white")
        loc = f"{escape(f.check)}  {escape(f.title)}  ({escape(f.file)}:{f.line})"
        head = f"[{style}]{f.decision.upper()}[/{style}]  {loc}"
        body = (
            f"likelihood={f.likelihood:.2f}  impact={f.impact:.2f}\n"
            f"[dim]{escape(f.rationale)}[/dim]\n"
            + "\n".join(f"  ↳ {escape(e)}" for e in f.evidence)
        )
        console.print(Panel(body, title=head, title_align="left", border_style=style))
    blocks = sum(1 for f in findings if f.decision == "block")
    reviews = sum(1 for f in findings if f.decision == "review")
    # Unjudged is subtracted explicitly. Folding it into the pass count would
    # report a finding nobody judged as one that came back clean.
    passes = len(findings) - blocks - reviews - unjudged
    tail = f" · {unjudged} unjudged" if unjudged else ""
    console.print(
        f"\n{blocks} block · {reviews} review · {passes} pass{tail}  "
        f"({report.files_scanned} file(s), {len(findings) - unjudged} finding(s) judged)"
    )
