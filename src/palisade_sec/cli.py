"""Palisade CLI: `palisade-sec scan` and `palisade-sec baseline`.

Exit codes:
  0 - success (no findings; or nothing new vs. baseline; or non-CI mode)
  1 - --ci and at least one NEW HIGH finding
  2 - usage / target errors
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
        "Palisade - security tooling for LLM apps. Statically detects prompt-injection "
        "paths (untrusted input -> LLM -> dangerous sink) in Python and "
        "JavaScript/TypeScript. The core (scan, map, baseline, fix) is offline and "
        "keyless; audit and review add a judgment layer over an endpoint you configure "
        "in .env. Everything is MIT and free to run."
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
    sarif: bool = typer.Option(
        False, "--sarif", help="Emit SARIF 2.1.0 to stdout (for GitHub code scanning)."
    ),
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
    """Scan a project (Python, JavaScript/TypeScript) for prompt-injection-to-sink paths."""
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

    if sarif:
        import os

        from palisade_sec.report import to_sarif

        # SARIF URIs must be relative to the repo root (cwd in CI), but finding
        # paths are relative to the scan target. Prepend the scan base so a
        # `scan src` places alerts at src/... not at the repo root.
        root = target.resolve()
        base = root if root.is_dir() else root.parent
        base_uri = os.path.relpath(base, Path.cwd()).replace(os.sep, "/")
        if base_uri.startswith(".."):  # scan target outside cwd: best effort
            base_uri = ""
        typer.echo(to_sarif(findings, base_uri=base_uri), nl=False)
    elif json_out:
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
            suppressed=len(result.suppressed),
        )

    if report:
        out = Path("palisade-report.md")
        out.write_text(to_markdown(findings, result.files_scanned, str(target)), encoding="utf-8")
        if not json_out and not sarif:
            typer.echo(f"report written to {out}")

    if ci and any(f.severity == "high" for f in findings):
        raise typer.Exit(1)


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
        raise typer.Exit(2)

    result = run_scan(
        target,
        config_file=config,
        rules_dir=rules,
        assume_params_untrusted=assume_params_untrusted or None,
    )
    findings = [f for f in result.findings if show_all or f.severity == "high" or f.risky]
    console = Console(highlight=False)
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


@app.command(name="map")
def map_cmd(
    path: str = typer.Argument(".", help="File or directory to inventory."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    config: str | None = typer.Option(
        None, "--config", help="Config file (.palisade.toml format)."
    ),
) -> None:
    """Inventory the codebase's AI surface: LLM calls, prompts, tools, agents,
    retrieval, and dangerous config flags.

    Deterministic and OFFLINE - like `scan`, it makes no network calls and needs
    no API key. This is the foundation the semantic `audit` checks build on.
    """
    from palisade_sec.scanner import lower_project
    from palisade_sec.semantic.inventory import build_map, print_map, to_json

    target = Path(path)
    if not target.exists():
        typer.echo(f"error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    low = lower_project(target, config)
    ai_map = build_map(low.modules)
    if json_out:
        typer.echo(to_json(ai_map, low.files_scanned), nl=False)
    else:
        console = Console(highlight=False)
        for w in low.warnings:
            console.print(f"[yellow]warning:[/yellow] {w}")
        print_map(console, ai_map, low.files_scanned)


@app.command()
def redteam(
    path: str = typer.Argument(".", help="File or directory to target."),
    json_out: bool = typer.Option(False, "--json", help="Emit as JSON."),
    variants: int = typer.Option(2, "--variants", help="Attack variants per target (1-5)."),
    execute: bool = typer.Option(
        False, "--execute", help="Fire the suite at a live target (needs --approve)."
    ),
    approve: bool = typer.Option(
        False, "--approve", help="Required with --execute: you authorize firing at the target."
    ),
    target_url: str | None = typer.Option(
        None, "--target", help="Target endpoint URL (or set PALISADE_REDTEAM_TARGET)."
    ),
    ci: bool = typer.Option(
        False, "--ci", help="With --execute: exit non-zero if any attack lands."
    ),
    config: str | None = typer.Option(
        None, "--config", help="Config file (.palisade.toml format)."
    ),
) -> None:
    """Synthesize a targeted adversarial attack suite from the AI System Map, and
    optionally execute it against a live target you own.

    Default is ADVISORY and OFFLINE: it generates attacks aimed at your
    tools/prompts/agents but does NOT run them. `--execute` (which requires
    `--approve`) fires the suite at the endpoint you provide (`--target` or
    PALISADE_REDTEAM_TARGET), in your environment, and scores what landed using
    the judgment backend from `.env`. Never run it against systems you do not own.
    """
    from palisade_sec.scanner import lower_project
    from palisade_sec.semantic.inventory import build_map
    from palisade_sec.semantic.redteam import plan, plan_to_json, print_plan

    target = Path(path)
    if not target.exists():
        typer.echo(f"error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    low = lower_project(target, config)
    ai_map = build_map(low.modules)
    cases = plan(ai_map, variants=max(1, min(5, variants)))

    if not execute:
        if json_out:
            typer.echo(plan_to_json(cases, low.files_scanned), nl=False)
        else:
            print_plan(Console(highlight=False), cases, low.files_scanned)
        return

    _redteam_execute(cases, approve=approve, target_url=target_url, json_out=json_out, ci=ci)


def _redteam_execute(cases, *, approve: bool, target_url: str | None, json_out: bool, ci: bool):
    import os

    from palisade_sec.judge.base import JudgeError
    from palisade_sec.judge.config import get_backend
    from palisade_sec.semantic.redteam import (
        BackendScorer,
        CompositeScorer,
        DeterministicScorer,
        HttpTarget,
        print_report,
        report_to_json,
        run,
    )

    if not approve:
        typer.echo(
            "error: --execute requires --approve. It fires adversarial inputs at a "
            "live target; run it only against systems you own and authorize.",
            err=True,
        )
        raise typer.Exit(2)
    url = target_url or os.environ.get("PALISADE_REDTEAM_TARGET")
    if not url:
        typer.echo("error: no target. Pass --target URL or set PALISADE_REDTEAM_TARGET.", err=True)
        raise typer.Exit(2)
    try:
        backend = get_backend()
    except JudgeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    target = HttpTarget(endpoint=url, api_key=os.environ.get("PALISADE_REDTEAM_KEY"))
    scorer = CompositeScorer(DeterministicScorer(), BackendScorer(backend))
    report = run(cases, target, scorer, approved=True)

    if json_out:
        typer.echo(report_to_json(report), nl=False)
    else:
        print_report(Console(highlight=False), report)
    if ci and report.landed:
        raise typer.Exit(1)


@app.command()
def audit(
    path: str = typer.Argument(".", help="File or directory to audit."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    ci: bool = typer.Option(
        False, "--ci", help="CI mode: exit non-zero if any tool is a BLOCK decision."
    ),
    config: str | None = typer.Option(
        None, "--config", help="Config file (.palisade.toml format)."
    ),
) -> None:
    """AI-safety audit (judgment tier): excessive-agency and taint-path exploitability.

    UNLIKE `scan`, this is bring-your-own-endpoint: it reads the judgment backend
    from `.env` (see .env.example) and sends small, IR-verified snippets (tool
    names and their dangerous call sites) to that endpoint. `scan`, `map`, and
    `baseline` stay fully offline and keyless.
    """
    from palisade_sec.judge.base import JudgeError
    from palisade_sec.judge.config import describe, get_backend
    from palisade_sec.semantic.audit import print_findings, run_audit, to_json

    target = Path(path)
    if not target.exists():
        typer.echo(f"error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    try:
        backend = get_backend()
    except JudgeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    if not json_out:
        console = Console(highlight=False, stderr=True)
        console.print(
            f"[yellow]note:[/yellow] `audit` sends IR-verified snippets to your "
            f"configured backend: {describe(backend)}. `scan` stays offline."
        )

    report = run_audit(target, backend, config_file=config)

    if json_out:
        typer.echo(to_json(report), nl=False)
    else:
        print_findings(Console(highlight=False), report)

    if ci and any(f.decision == "block" for f in report.findings):
        raise typer.Exit(1)


@app.command()
def review(
    path: str = typer.Argument(".", help="File or directory to review."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    report_out: bool = typer.Option(
        False, "--report", help="Write a markdown report to palisade-review.md."
    ),
    ci: bool = typer.Option(
        False, "--ci", help="CI mode: exit non-zero on a new HIGH taint finding (baseline-diffed)."
    ),
    baseline: str | None = typer.Option(
        None, "--baseline", help=f"Baseline file to diff --ci against (e.g. {DEFAULT_BASELINE})."
    ),
    config: str | None = typer.Option(
        None, "--config", help="Config file (.palisade.toml format)."
    ),
) -> None:
    """One prioritized report with a posture score, composing scan + map + the
    semantic checks + red-team synthesis.

    If a judgment backend is configured in `.env`, findings are judged and the
    posture reflects that (labelled, and capped for an unverified backend). If
    not, the review runs taint-only and says so. `--ci` gates only on NEW HIGH
    taint findings (deterministic); judged signals are advisory and never gate.
    """
    from palisade_sec.baseline import diff_against_baseline
    from palisade_sec.judge.base import JudgeError
    from palisade_sec.judge.config import get_backend
    from palisade_sec.semantic.review import print_review, run_review, to_json, to_markdown

    target = Path(path)
    if not target.exists():
        typer.echo(f"error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    backend = None
    try:
        backend = get_backend()
    except JudgeError:
        backend = None  # taint-only review; labelled in the report

    result = run_review(target, backend, config_file=config)

    if json_out:
        typer.echo(to_json(result), nl=False)
    else:
        print_review(Console(highlight=False), result)

    if report_out:
        out = Path("palisade-review.md")
        out.write_text(to_markdown(result, str(target)), encoding="utf-8")
        if not json_out:
            typer.echo(f"report written to {out}")

    if ci:
        findings = result.taint_findings
        if baseline:
            findings = diff_against_baseline(findings, Path(baseline)).new
        if any(f.severity == "high" for f in findings):
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
