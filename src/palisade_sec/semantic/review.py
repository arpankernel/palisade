"""`palisade-sec review`: one prioritized report over everything Palisade knows.

It composes existing signals - taint findings, the AI System Map, the semantic
checks, and the red-team synthesis - into a single risk-ranked view with a
posture score. It adds no new detection surface of its own.

Posture is a number (0..100) and a named band, derived from the tier counts and
printed with the breakdown beside it. It is a posture over DETECTED findings,
computed from likelihood x impact - not a safety score, and not a pass
certificate. When the judgment layer ran, the score inherits its uncalibrated,
possibly-unverified status; when it did not, the score is taint-only and says so.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rich.markup import escape

from palisade_sec.engine import Finding
from palisade_sec.judge.base import JudgeBackend
from palisade_sec.semantic.audit import (
    audit_excessive_agency,
    audit_taint_exploitability,
)
from palisade_sec.semantic.inventory import build_map
from palisade_sec.semantic.policy import SemanticPolicy
from palisade_sec.semantic.redteam import synthesize
from palisade_sec.semantic.risk import (
    critical_band_allowed,
    more_severe_band,
    posture_band,
    posture_score,
    static_impact,
    static_likelihood,
    tier_of,
    worst_band,
)


@dataclass
class RiskItem:
    kind: str  # "taint" | "excessive_agency"
    title: str
    file: str
    line: int
    likelihood: float
    impact: float
    verified: bool
    judged: bool
    evidence: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    @property
    def risk(self) -> float:
        return self.likelihood * self.impact

    @property
    def tier(self) -> str:
        return tier_of(self.risk, self.verified)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "likelihood": round(self.likelihood, 3),
            "impact": round(self.impact, 3),
            "risk": round(self.risk, 3),
            "tier": self.tier,
            "verified": self.verified,
            "judged": self.judged,
            "evidence": self.evidence,
            "detail": self.detail,
        }


@dataclass
class ReviewReport:
    items: list[RiskItem]
    taint_findings: list[Finding]
    ai_surface: dict
    attacks_synthesized: int
    files_scanned: int
    judged: bool
    backend_name: str | None
    backend_verified: bool

    def breakdown(self) -> dict[str, int]:
        counts = Counter(i.tier for i in self.items)
        return {t: counts.get(t, 0) for t in ("critical", "high", "moderate", "low")}

    def posture(self) -> tuple[int, str]:
        counts = self.breakdown()
        score = posture_score(counts)
        # The band is the more severe of the score-derived band and the worst
        # individual tier, so one critical finding is never averaged away.
        band = more_severe_band(posture_band(score), worst_band([i.tier for i in self.items]))
        # A Critical posture requires a verified high/critical signal, so an
        # unverified backend cannot manufacture one on judgment alone.
        if band == "Critical" and not critical_band_allowed(
            [(i.verified, i.tier) for i in self.items]
        ):
            band = "High"
        return score, band

    def to_dict(self) -> dict:
        score, band = self.posture()
        return {
            "tool": "palisade-sec review",
            "schema_version": 1,
            "posture": {
                "score": score,
                "band": band,
                "over": "detected findings (likelihood x impact)",
                "judged": self.judged,
                "backend": self.backend_name,
                "backend_verified": self.backend_verified,
                "uncalibrated": self.judged,
            },
            "breakdown": self.breakdown(),
            "files_scanned": self.files_scanned,
            "ai_surface": self.ai_surface,
            "attacks_synthesized": self.attacks_synthesized,
            "items": [i.to_dict() for i in sorted(self.items, key=lambda x: -x.risk)],
        }


def run_review(
    target: Path,
    backend: JudgeBackend | None,
    config_file: str | None = None,
    policy: SemanticPolicy | None = None,
) -> ReviewReport:
    """Compose the review. `backend=None` means taint-only (offline) posture."""
    from palisade_sec.scanner import lower_project, run_scan

    scan = run_scan(target, config_file=config_file)
    low = lower_project(target, config_file)
    ai_map = build_map(low.modules)
    attacks = synthesize(ai_map)

    exploitability = []
    agency = []
    if backend is not None:
        agency = audit_excessive_agency(low.modules, backend, policy)
        exploitability = audit_taint_exploitability(scan.findings, backend, policy)

    items = _risk_items(scan.findings, exploitability, agency)
    return ReviewReport(
        items=items,
        taint_findings=scan.findings,
        ai_surface=ai_map.summary(),
        attacks_synthesized=len(attacks),
        files_scanned=low.files_scanned,
        judged=backend is not None,
        backend_name=backend.name if backend is not None else None,
        backend_verified=backend.verified if backend is not None else True,
    )


def _risk_items(taint_findings, exploitability, agency) -> list[RiskItem]:
    items: list[RiskItem] = []
    expl_by_fp = {f.detail["fingerprint"]: f for f in exploitability}
    for tf in taint_findings:
        ef = expl_by_fp.get(tf.fingerprint)
        sink_name = tf.sink.file.rsplit("/", 1)[-1]
        if ef is not None:
            # A taint path is a verified fact; its risk basis is always verified.
            # `_honest_li` already left the risk at the static value when the
            # backend was unverified, so `judged` reflects a real refinement only.
            likelihood, impact, verified = ef.likelihood, ef.impact, True
            judged = ef.verified
            evidence = ef.evidence
        else:
            likelihood = static_likelihood(tf.confidence, tf.risky)
            impact = static_impact(tf.severity)
            verified, judged = True, False
            evidence = [
                f"source: {tf.source.snippet} ({tf.source.file}:{tf.source.line})",
                f"sink:   {tf.sink.snippet} ({tf.sink.file}:{tf.sink.line})",
            ]
        items.append(
            RiskItem(
                kind="taint",
                title=f"{tf.rule_id} -> {sink_name}:{tf.sink.line}",
                file=tf.sink.file,
                line=tf.sink.line,
                likelihood=likelihood,
                impact=impact,
                verified=verified,
                judged=judged,
                evidence=evidence,
                detail={
                    "rule_id": tf.rule_id,
                    "severity": tf.severity,
                    "confidence": tf.confidence,
                },
            )
        )
    for af in agency:
        items.append(
            RiskItem(
                kind="excessive_agency",
                title=af.title,
                file=af.file,
                line=af.line,
                likelihood=af.likelihood,
                impact=af.impact,
                verified=af.verified,
                judged=True,
                evidence=af.evidence,
                detail=af.detail,
            )
        )
    return items


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_TIER_STYLE = {"critical": "bold red", "high": "red", "moderate": "yellow", "low": "green"}


def _backend_label(report: ReviewReport) -> str:
    if not report.judged:
        return "taint-only: no judgment backend configured; exploitability not assessed"
    base = (
        f"judgment layer used ({report.backend_name}); the exploitability signal "
        "is uncalibrated until scored on the corpus"
    )
    if not report.backend_verified:
        base += "; best-effort/unverified backend, so blocks and Critical posture are capped"
    return base


def to_json(report: ReviewReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def print_review(console, report: ReviewReport) -> None:
    score, band = report.posture()
    b = report.breakdown()
    console.print(
        f"\n[bold]Palisade review[/bold]  ·  "
        f"Posture [bold]{score}/100[/bold] ({band}) over {len(report.items)} detected finding(s)"
    )
    console.print(
        f"  [{_TIER_STYLE['critical']}]Critical {b['critical']}[/]  "
        f"[{_TIER_STYLE['high']}]High {b['high']}[/]  "
        f"[{_TIER_STYLE['moderate']}]Moderate {b['moderate']}[/]  "
        f"[{_TIER_STYLE['low']}]Low {b['low']}[/]"
    )
    console.print(f"  [dim]{escape(_backend_label(report))}[/dim]")
    s = report.ai_surface
    console.print(
        f"  [dim]AI surface: {s['llm_calls']} LLM call(s), {s['prompts']} prompt(s), "
        f"{s['tools']} tool(s), {s['agents']} agent(s); "
        f"{report.attacks_synthesized} adversarial test(s) synthesized (advisory, not run)[/dim]\n"
    )

    if not report.items:
        console.print("[green]No findings detected.[/green]")
    for item in sorted(report.items, key=lambda x: -x.risk):
        style = _TIER_STYLE.get(item.tier, "white")
        judged = "judged" if item.judged else "static"
        console.print(
            f"[{style}]{item.tier.upper():8}[/] risk={item.risk:.2f} "
            f"[dim]({judged}, L={item.likelihood:.2f} I={item.impact:.2f})[/dim]  "
            f"{escape(item.title)}  [dim]{escape(item.file)}:{item.line}[/dim]"
        )
    console.print(
        "\n[dim]A clean posture is not a proof of safety; it reflects detected "
        "findings only. Keep your runtime guardrails and sandboxes.[/dim]"
    )


def to_markdown(report: ReviewReport, target: str) -> str:
    score, band = report.posture()
    b = report.breakdown()
    lines = [
        "# Palisade review",
        "",
        f"**Posture: {score}/100 ({band})** over {len(report.items)} detected finding(s), "
        "computed as likelihood x impact. This is a posture over detected findings, "
        "not a safety score.",
        "",
        f"- Critical: {b['critical']} · High: {b['high']} · Moderate: {b['moderate']} "
        f"· Low: {b['low']}",
        f"- {_backend_label(report)}",
        f"- Target: `{target}` ({report.files_scanned} file(s))",
        f"- AI surface: {report.ai_surface['llm_calls']} LLM call(s), "
        f"{report.ai_surface['prompts']} prompt(s), {report.ai_surface['tools']} tool(s), "
        f"{report.ai_surface['agents']} agent(s)",
        f"- {report.attacks_synthesized} adversarial test(s) synthesized (advisory, not run)",
        "",
        "## Findings by risk",
        "",
        "| Tier | Risk | Kind | Finding | Location | Judged |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in sorted(report.items, key=lambda x: -x.risk):
        lines.append(
            f"| {item.tier} | {item.risk:.2f} | {item.kind} | {item.title} | "
            f"`{item.file}:{item.line}` | {'yes' if item.judged else 'static'} |"
        )
    lines += [
        "",
        "> A clean posture is not a proof of safety; it reflects detected findings only.",
        "",
    ]
    return "\n".join(lines)
