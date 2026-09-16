"""Rich terminal emitter. Scannable and teaching: every finding shows the
data-flow trace, the concrete attack, and the specific fix.

Color is disabled automatically on non-TTY output (UX-3) - rich handles that,
and NO_COLOR is respected.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from palisade_sec.engine import Finding

_SEV_STYLE = {"high": "bold red", "med": "bold yellow", "low": "bold cyan"}
_SEV_LABEL = {"high": "HIGH", "med": "MED", "low": "LOW"}


def print_findings(
    console: Console,
    findings: list[Finding],
    files_scanned: int,
    skipped: list[str],
    warnings: list[str],
    notes: list[str],
    shown_all: bool = False,
    hidden_count: int = 0,
    baseline_known: int = 0,
) -> None:
    for w in warnings:
        console.print(f"[yellow]warning:[/yellow] {escape(w)}")
    for s in skipped:
        console.print(f"[yellow]skipped:[/yellow] {escape(s)}")

    for f in findings:
        console.print()
        header = Text()
        header.append(_SEV_LABEL[f.severity].ljust(5), style=_SEV_STYLE[f.severity])
        header.append(f"{f.file}:{f.line}  ", style="bold")
        header.append(f"[{f.rule_id}] ", style="magenta")
        header.append(f.title)
        if f.risky:
            header.append("  (risky: partial defense only)", style="yellow")
        console.print(header)

        def arrow(label: str, tp) -> None:
            line = Text("  ↳ ")
            line.append(f"{label}:".ljust(8), style="dim")
            line.append(tp.snippet or tp.detail, style="white")
            line.append(f"  ({tp.file}:{tp.line})", style="dim")
            console.print(line)

        arrow("source", f.source)
        arrow("llm", f.llm)
        arrow("sink", f.sink)

        if f.partial_defenses:
            gates = [p for p in f.partial_defenses if p.kind != "unverified_sanitizer"]
            unverified = [p for p in f.partial_defenses if p.kind == "unverified_sanitizer"]
            if gates:
                what = escape(", ".join(f"{p.pattern} ({p.file}:{p.line})" for p in gates))
                console.print(
                    f"  [yellow]Partial defense only:[/yellow] {what} - "
                    "denylists and confirmation gates have been bypassed in real CVEs."
                )
            if unverified:
                what = escape(", ".join(f"{p.pattern} ({p.file}:{p.line})" for p in unverified))
                console.print(
                    f"  [yellow]Unverified sanitizer:[/yellow] {what} - "
                    "matches a sanitizer name, but its body shows no "
                    "allowlist/validation shape."
                )
        else:
            console.print("  [dim]No sanitizer on path.[/dim]", end="")
            console.print(f"  Confidence: [bold]{f.confidence}[/bold]")
        if f.partial_defenses:
            console.print(f"  Confidence: [bold]{f.confidence}[/bold]")
        if f.attack.strip():
            console.print(f"  [bold]Attack:[/bold] {f.attack.strip()}")
        if f.fix.strip():
            console.print(f"  [bold]Fix:[/bold]    {f.fix.strip()}")
        if f.references:
            console.print(f"  [dim]Refs:   {'; '.join(f.references)}[/dim]")
        if f.count > 1:
            console.print(f"  [dim]({f.count} occurrences share this fingerprint)[/dim]")

    console.print()
    for n in notes:
        console.print(f"[dim]note: {escape(n)}[/dim]")
    if not findings:
        if baseline_known:
            console.print(
                f"[green]✓ No new findings.[/green] "
                f"({baseline_known} known finding(s) suppressed by baseline; "
                f"{files_scanned} file(s) scanned)"
            )
        else:
            console.print(
                f"[green]✓ No LLM injection paths found.[/green] ({files_scanned} file(s) scanned)"
            )
    else:
        high = sum(1 for f in findings if f.severity == "high")
        med = sum(1 for f in findings if f.severity == "med")
        low = sum(1 for f in findings if f.severity == "low")
        parts = []
        if high:
            parts.append(f"[bold red]{high} high[/bold red]")
        if med:
            parts.append(f"[bold yellow]{med} med[/bold yellow]")
        if low:
            parts.append(f"[bold cyan]{low} low[/bold cyan]")
        summary = ", ".join(parts)
        console.print(f"Found {summary} finding(s) in {files_scanned} file(s).")
        if baseline_known:
            console.print(f"[dim]{baseline_known} known finding(s) suppressed by baseline.[/dim]")
    if hidden_count and not shown_all:
        console.print(
            f"[dim]{hidden_count} MED/LOW finding(s) hidden - run with --all to see them.[/dim]"
        )
