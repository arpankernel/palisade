import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_APP = REPO_ROOT / "examples" / "vulnerable-app"

sys.path.insert(0, str(REPO_ROOT / "src"))


@pytest.fixture(scope="session")
def example_scan():
    from palisade_sec.scanner import run_scan

    return run_scan(EXAMPLE_APP)


def find_line(file: Path, needle: str, after: str | None = None) -> int:
    """1-based line number of the first line containing `needle`, optionally
    only after the first line containing `after` (e.g. a def line)."""
    lines = file.read_text().splitlines()
    start = 0
    if after is not None:
        for i, line in enumerate(lines):
            if after in line:
                start = i + 1
                break
        else:
            raise AssertionError(f"marker {after!r} not found in {file}")
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    raise AssertionError(f"{needle!r} not found in {file} after {after!r}")


def func_range(file: Path, def_name: str) -> tuple[int, int]:
    """(start, end) 1-based line range of a top-level function body."""
    lines = file.read_text().splitlines()
    start = None
    for i, line in enumerate(lines):
        if start is None:
            if line.startswith(f"def {def_name}(") or f"def {def_name}(" in line:
                start = i + 1
        else:
            if line and not line[0].isspace() and not line.startswith(("@", ")")):
                return start, i
    if start is None:
        raise AssertionError(f"def {def_name} not found in {file}")
    return start, len(lines)
