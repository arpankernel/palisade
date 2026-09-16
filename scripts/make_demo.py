"""Regenerate docs/demo.svg — the README hero: a real scan of the example
app, rendered by rich and exported as SVG.

Usage: uv run python scripts/make_demo.py
"""

import re
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
    svg = console.export_svg(title="palisade-sec")
    # rich emits viewBox-only SVGs; PyPI's CSS renders those at 0x0 unless
    # the root carries explicit width/height (GitHub is more forgiving).
    match = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    if match and "width=" not in svg[: svg.index(">")]:
        w, h = match.group(1), match.group(2)
        svg = svg.replace('viewBox="0 0', f'width="{w}" height="{h}" viewBox="0 0', 1)
    OUT.write_text(svg, encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
