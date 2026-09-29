"""The "install the optional extra" hints must survive being printed.

Rich reads `[js]` and `[judge]` as style tags. A hint printed through
`console.print` therefore came out as `pip install 'palisade-sec'` - a
command that succeeds, installs nothing, and leaves the user with a
feature that still does not work and no error to search for. Worse than a
typo: a silent dead end at exactly the moment someone is trying to enable
a feature.

Two layers here: the emitted text of the real commands, and a guard over
every extras hint in the source, so a future `console.print` of one fails
here instead of in someone's terminal.
"""

from __future__ import annotations

import io
import re
import subprocess
import sys
from pathlib import Path

import pytest
from rich.console import Console

SRC = Path(__file__).resolve().parent.parent / "src" / "palisade_sec"

# `pip install 'palisade-sec[js]'`, `uvx --from 'palisade-sec[judge]'`, ...
EXTRA_RE = re.compile(r"palisade-sec\[(\w+)\]")

BLOCK_JS = """
import sys
BLOCKED = {"tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript"}
class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ImportError(name + " blocked for this test")
        return None
sys.meta_path.insert(0, Block())
from palisade_sec.cli import run
run()
"""


def _hint_sources() -> list[tuple[Path, int, str]]:
    """Every line of shipped source that names an extra."""
    out = []
    for path in sorted(SRC.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if EXTRA_RE.search(line):
                out.append((path, lineno, line.strip()))
    return out


def test_the_guard_actually_finds_the_hints() -> None:
    """Vacuity check: if the walk finds nothing, everything below passes for
    free and pins nothing at all."""
    hints = _hint_sources()
    assert len(hints) >= 4, f"expected the extras hints to be found, got {hints}"
    assert {EXTRA_RE.search(line).group(1) for _, _, line in hints} >= {"js", "judge"}


@pytest.mark.parametrize("extra", ["js", "judge", "keyring"])
def test_rich_would_eat_a_bare_extra(extra: str) -> None:
    """The mechanism itself, pinned. If a rich upgrade ever stops treating
    `[js]` as a tag, the escaping below becomes unnecessary - this test
    turning red is how we would find out."""
    buf = io.StringIO()
    Console(file=buf, width=200, force_terminal=False).print(f"pip install 'palisade-sec[{extra}]'")
    assert f"[{extra}]" not in buf.getvalue(), "rich no longer eats extras; the guard can relax"


def test_no_extras_hint_is_printed_through_rich_markup() -> None:
    """A `console.print` of an extras hint is the bug. Use `typer.echo`, or
    pass `markup=False`."""
    offenders = []
    for path, lineno, line in _hint_sources():
        if "console.print" in line or "[/dim]" in line or "[/yellow]" in line:
            offenders.append(f"{path.relative_to(SRC.parent.parent)}:{lineno}: {line}")
    assert not offenders, (
        "these print an extras name through rich, which will delete it - "
        "use typer.echo or markup=False:\n  " + "\n  ".join(offenders)
    )


def _run_cli(tmp_path: Path, args: list[str]) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", BLOCK_JS, *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(Path(__file__).resolve().parent.parent),
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "PALISADE_NO_KEYRING": "1",
            "COLUMNS": "200",
        },
    )
    return proc.stdout + proc.stderr


@pytest.fixture
def js_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.js").write_text('const e = require("express");\n')
    return repo


@pytest.mark.parametrize("command", ["scan", "baseline"])
def test_the_js_hint_survives_every_command_that_prints_it(
    command: str, tmp_path: Path, js_repo: Path
) -> None:
    """`scan` and `baseline` emit the identical warning through different
    renderers; only one of them used to get it right."""
    args = [command, str(js_repo)]
    if command == "baseline":
        args += ["--output", str(tmp_path / "baseline.json")]
    output = _run_cli(tmp_path, args).replace("\n", "")
    assert "JS/TS file(s) skipped" in output, output
    assert "palisade-sec[js]" in output, (
        f"`{command}` printed an install command with the extra stripped out:\n{output}"
    )
