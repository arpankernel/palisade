"""Regenerate docs/demo.svg — the README hero: a real scan of the example
app, rendered by rich and exported as SVG.

Usage: uv run python scripts/make_demo.py
"""

from pathlib import Path

from rich.console import Console

from palisade_sec.report.terminal import print_findings
from palisade_sec.scanner import run_scan

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "examples" / "vulnerable-app"
OUT = ROOT / "docs" / "demo.svg"


def main() -> None:
    result = run_scan(TARGET)
    visible = [f for f in result.findings if f.severity == "high" or f.risky]
    console = Console(record=True, width=100, force_terminal=True)
    console.print("[bold green]$[/bold green] uvx palisade-sec scan .")
    print_findings(
        console,
        visible,
        result.files_scanned,
        result.skipped,
        result.warnings,
        result.notes,
        shown_all=False,
        hidden_count=len(result.findings) - len(visible),
    )
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(console.export_svg(title="palisade-sec"), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
