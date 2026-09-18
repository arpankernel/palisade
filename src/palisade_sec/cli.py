"""Palisade CLI: `palisade-sec scan` and `palisade-sec baseline`.

Exit codes:
  0 - success (no findings; or nothing new vs. baseline; or non-CI mode)
  1 - --ci and at least one NEW HIGH finding
  2 - usage / target errors
  3 - internal error: the scan did not complete, so its verdict is unknown

Code 3 exists so a CI gate can tell "Palisade ran and found a HIGH" (1) from
"Palisade crashed and proved nothing" (previously also 1, via an uncaught
traceback). A security gate that fails open on its own bugs is worse than one
that fails loudly.
"""

from __future__ import annotations

from pathlib import Path

import typer

from palisade_sec import __version__
from palisade_sec.baseline import (
    DEFAULT_BASELINE,
    diff_against_baseline,
    write_baseline,
)
from palisade_sec.report import make_console, print_findings, to_json, to_markdown
from palisade_sec.scanner import ScanResult, run_scan

app = typer.Typer(
    name="palisade-sec",
    help=(
        "Palisade - a linter for LLM security. Statically detects prompt-injection "
        "paths (untrusted input -> LLM -> dangerous sink) in Python code. "
        "Pure static analysis: no code execution, no network, no API key."
    ),
    add_completion=False,
    no_args_is_help=True,
)


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"palisade-sec {__version__}")
        raise typer.Exit()


def _scan_or_exit(
    target: Path,
    *,
    config_file: str | None = None,
    rules_dir: str | None = None,
    assume_params_untrusted: bool | None = None,
) -> ScanResult:
    """Run a scan behind a crash boundary.

    An unexpected exception here means the scan produced no trustworthy
    verdict. Report that distinctly (exit 3) instead of letting the traceback
    surface as exit 1, which a CI gate cannot tell from a real HIGH finding.
    """
    try:
        return run_scan(
            target,
            config_file=config_file,
            rules_dir=rules_dir,
            assume_params_untrusted=assume_params_untrusted,
        )
    except KeyboardInterrupt:
        typer.echo("error: interrupted; scan incomplete", err=True)
        raise typer.Exit(EXIT_INTERNAL) from None
    except Exception as exc:  # noqa: BLE001 - top-level boundary
        typer.echo(
            f"error: internal error during scan, results are incomplete: "
            f"{type(exc).__name__}: {exc}",
            err=True,
        )
        typer.echo(
            "this is a bug in palisade-sec - please report it at "
            "https://github.com/arpankernel/palisade/issues",
            err=True,
        )
        raise typer.Exit(EXIT_INTERNAL) from exc


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
    report_output: str | None = typer.Option(
        None,
        "--report-output",
        help="Path for the --report markdown file (default: palisade-report.md).",
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
        raise typer.Exit(EXIT_USAGE)

    result = _scan_or_exit(
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
                suppressed=result.suppressed,
            ),
            nl=False,
        )
    else:
        console = make_console()
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
            suppressed=len(result.suppressed),
        )

    if report or report_output:
        out = Path(report_output) if report_output else Path("palisade-report.md")
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                to_markdown(findings, result.files_scanned, str(target)), encoding="utf-8"
            )
        except OSError as exc:
            typer.echo(f"error: could not write report to {out}: {exc}", err=True)
            raise typer.Exit(EXIT_USAGE) from exc
        if not json_out:
            typer.echo(f"report written to {out}")

    if ci and any(f.severity == "high" for f in findings):
        raise typer.Exit(EXIT_FINDINGS)


@app.command()
def fix(
    path: str = typer.Argument(".", help="File or directory to scan."),
    output: str = typer.Option(
        "palisade-fixes.md", "--output", help="Remediation plan file to write."
    ),
    show_all: bool = typer.Option(
        False, "--all", help="Also cover MED/LOW findings (default: HIGH + risky)."
    ),
    rules: str | None = typer.Option(None, "--rules", help="Extra rules directory."),
    config: str | None = typer.Option(
        None, "--config", help="Config file (.palisade.toml format)."
    ),
    assume_params_untrusted: bool = typer.Option(
        False, "--assume-params-untrusted", help="Library mode (see `scan --help`)."
    ),
) -> None:
    """Generate a remediation plan: a guardrail + regression test per finding.

    Deterministic and offline - templates tailored per rule, no LLM calls,
    and the scanned project is never modified.
    """
    from palisade_sec.fix import build_fix_plan

    target = Path(path)
    if not target.exists():
        typer.echo(f"error: path does not exist: {path}", err=True)
        raise typer.Exit(EXIT_USAGE)

    result = _scan_or_exit(
        target,
        config_file=config,
        rules_dir=rules,
        assume_params_untrusted=assume_params_untrusted or None,
    )
    findings = [f for f in result.findings if show_all or f.severity == "high" or f.risky]
    console = make_console()
    for w in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")
    if not findings:
        console.print(
            f"[green]✓ No findings to fix.[/green] ({result.files_scanned} file(s) scanned)"
        )
        return
    out = Path(output)
    out.write_text(build_fix_plan(findings, result.files_scanned, str(target)), encoding="utf-8")
    console.print(
        f"remediation plan for {len(findings)} finding(s) written to {out} - "
        "each guardrail ships with a regression test; adapt the allowlists, "
        "then add the tests to your suite."
    )


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
        raise typer.Exit(EXIT_USAGE)

    result = _scan_or_exit(target, config_file=config, rules_dir=rules)
    root = target if target.is_dir() else target.parent
    out = Path(output) if output else root / DEFAULT_BASELINE
    write_baseline(result.findings, out)
    console = make_console()
    for w in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")
    console.print(
        f"baseline written to {out} "
        f"({len(result.findings)} finding(s) fingerprinted, "
        f"{result.files_scanned} file(s) scanned)"
    )


if __name__ == "__main__":
    app()
