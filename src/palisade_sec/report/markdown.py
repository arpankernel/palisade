"""Markdown report emitter (`--report` -> palisade-report.md): a shareable
mini threat model, grouped by severity."""

from __future__ import annotations

from datetime import UTC, datetime

from palisade_sec import __version__
from palisade_sec.engine import Finding

_SEV_TITLE = {"high": "HIGH", "med": "MED (risky / partial defense)", "low": "LOW"}


def to_markdown(findings: list[Finding], files_scanned: int, target: str) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Palisade scan report",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {now} by palisade-sec {__version__}",
        f"- **Files scanned:** {files_scanned}",
        f"- **Findings:** {len(findings)} "
        f"(high: {sum(1 for f in findings if f.severity == 'high')}, "
        f"med: {sum(1 for f in findings if f.severity == 'med')}, "
        f"low: {sum(1 for f in findings if f.severity == 'low')})",
        "",
        "> Palisade detects untrusted input flowing through an LLM into a "
        "dangerous sink. It is one layer of defense - a clean scan does not "
        "mean the application is secure.",
        "",
    ]
    if not findings:
        lines += ["**No LLM injection paths found.**", ""]
        return "\n".join(lines)

    for sev in ("high", "med", "low"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines += [f"## {_SEV_TITLE[sev]}", ""]
        for f in group:
            lines += [
                f"### [{f.rule_id}] {f.title} - `{f.file}:{f.line}`",
                "",
                f.attack.strip() and f"**Attack:** {f.attack.strip()}" or "",
                "",
                "**Data flow:**",
                "",
                "| Step | Location | Code |",
                "|------|----------|------|",
                f"| source | `{f.source.file}:{f.source.line}` | `{_code(f.source.snippet)}` |",
                f"| llm | `{f.llm.file}:{f.llm.line}` | `{_code(f.llm.snippet)}` |",
                f"| sink | `{f.sink.file}:{f.sink.line}` | `{_code(f.sink.snippet)}` |",
                "",
            ]
            if f.partial_defenses:
                gates = [p for p in f.partial_defenses if p.kind != "unverified_sanitizer"]
                unverified = [p for p in f.partial_defenses if p.kind == "unverified_sanitizer"]
                if gates:
                    what = ", ".join(f"`{p.pattern}` at `{p.file}:{p.line}`" for p in gates)
                    lines += [
                        f"**Partial defense only:** {what}. Denylists and confirmation "
                        "gates have been bypassed in real CVEs - this path is still risky.",
                        "",
                    ]
                if unverified:
                    what = ", ".join(f"`{p.pattern}` at `{p.file}:{p.line}`" for p in unverified)
                    lines += [
                        f"**Unverified sanitizer:** {what}. It matches a sanitizer name, "
                        "but its body shows no allowlist/validation shape - this path "
                        "is still risky.",
                        "",
                    ]
            else:
                lines += [f"No sanitizer on path. Confidence: **{f.confidence}**.", ""]
            if f.fix.strip():
                lines += [f"**Fix:** {f.fix.strip()}", ""]
            if f.references:
                lines += ["**References:** " + "; ".join(f.references), ""]
    return "\n".join(line for line in lines if line is not None)


def _code(s: str) -> str:
    return s.replace("|", "\\|").replace("`", "'")
