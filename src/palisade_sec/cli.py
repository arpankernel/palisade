"""Palisade CLI: `palisade-sec scan` and `palisade-sec baseline`.

Exit codes:
  0 — success (no findings; or nothing new vs. baseline; or non-CI mode)
  1 — --ci and at least one NEW HIGH finding
  2 — usage / target errors
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from palisade_sec import __version__
from palisade_sec.baseline import (
    DEFAULT_BASELINE,
    diff_against_baseline,
    write_baseline,
)
from palisade_sec.report import print_findings, to_json, to_markdown
from palisade_sec.scanner import run_scan

app = typer.Typer(
    name="palisade-sec",
    help=(
        "Palisade — a linter for LLM security. Statically detects prompt-injection "
        "paths (untrusted input -> LLM -> dangerous sink) in Python code. "
        "Pure static analysis: no code execution, no network, no API key."
    ),
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"palisade-sec {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True),
) -> None:
    pass


@app.command()
def scan(
    path: str = typer.Argument(".", help="File or directory to scan."),
    show_all: bool = typer.Option(
        False, "--all", help="Also show MED/LOW findings (default: HIGH + risky)."
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    report: bool = typer.Option(
        False, "--report", help="Write a markdown report to palisade-report.md."
    ),
    ci: bool = typer.Option(
        False, "--ci", help="CI mode: exit non-zero if any (new) HIGH finding."
    ),
    baseline: str | None = typer.Option(
        None, "--baseline", help=f"Baseline file to diff against (e.g. {DEFAULT_BASELINE})."
    ),
    rules: str | None = typer.Option(None, "--rules", help="Extra rules directory."),
    config: str | None = typer.Option(
        None, "--config", help="Config file (.palisade.toml format)."
    ),
    assume_params_untrusted: bool = typer.Option(
        False,
        "--assume-params-untrusted",
        help=(
            "Library mode: treat parameters of public functions as untrusted "
            "sources (for auditing libraries, which have no visible caller)."
        ),
    ),
) -> None:
    """Scan a Python project for prompt-injection-to-sink paths."""
    target = Path(path)
    if not target.exists():
        typer.echo(f"error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    result = run_scan(
        target,
        config_file=config,
        rules_dir=rules,
        assume_params_untrusted=assume_params_untrusted or None,
    )
    findings = result.findings

    baseline_known = 0
    if baseline:
        diff = diff_against_baseline(findings, Path(baseline))
        result.warnings.extend(diff.warnings)
        baseline_known = len(diff.known)
        findings = diff.new
        if diff.stale:
            result.notes.append(
                f"{len(diff.stale)} stale baseline entrie(s) no longer present "
                "(re-run `palisade-sec baseline` to refresh)"
            )

    # Display policy (UX-5): HIGH always; MED shown when it is a downgraded
    # "risky" finding (partial defense) so real risk is never silent; --all
    # shows everything.
    visible = [f for f in findings if show_all or f.severity == "high" or f.risky]
    hidden = len(findings) - len(visible)

    if json_out:
        typer.echo(
            to_json(
                findings,
                result.files_scanned,
                result.skipped,
                result.warnings,
                result.notes,
                baseline_suppressed=baseline_known,
            ),
            nl=False,
        )
    else:
        console = Console(highlight=False)
        print_findings(
            console,
            visible,
            result.files_scanned,
            result.skipped,
            result.warnings,
            result.notes,
            shown_all=show_all,
            hidden_count=hidden,
            baseline_known=baseline_known,
        )

    if report:
        out = Path("palisade-report.md")
        out.write_text(to_markdown(findings, result.files_scanned, str(target)), encoding="utf-8")
        if not json_out:
            typer.echo(f"report written to {out}")

    if ci and any(f.severity == "high" for f in findings):
        raise typer.Exit(1)


@app.command()
def baseline(
    path: str = typer.Argument(".", help="File or directory to scan."),
    output: str | None = typer.Option(
        None, "--output", help=f"Baseline file to write (default: <path>/{DEFAULT_BASELINE})."
    ),
    rules: str | None = typer.Option(None, "--rules", help="Extra rules directory."),
    config: str | None = typer.Option(
        None, "--config", help="Config file (.palisade.toml format)."
    ),
) -> None:
    """Fingerprint current findings so CI fails only on NEW ones."""
    target = Path(path)
    if not target.exists():
        typer.echo(f"error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    result = run_scan(target, config_file=config, rules_dir=rules)
    root = target if target.is_dir() else target.parent
    out = Path(output) if output else root / DEFAULT_BASELINE
    write_baseline(result.findings, out)
    console = Console(highlight=False)
    for w in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")
    console.print(
        f"baseline written to {out} "
        f"({len(result.findings)} finding(s) fingerprinted, "
        f"{result.files_scanned} file(s) scanned)"
    )


if __name__ == "__main__":
    app()
