"""Inline suppressions: `# palisade: ignore[PI-EXEC] - reviewed, sandboxed`.

Phase 0 requires these for two reasons. The benchmark corpus contains repos
that knowingly carry accepted risk, and no real codebase adopts a scanner
that has even one finding it cannot silence: "one unfixable finding disables
the tool" otherwise.

Suppressions are deliberately *loud*. Every one is counted, every one is
attributable to a line and a reason, and any that stops matching anything is
reported as stale. A silent suppression mechanism in a security tool is how
a vulnerability quietly returns.

Syntax (Python `#`, JS/TS `//`):

    exec(code)  # palisade: ignore[PI-EXEC] - runs in a locked-down sandbox
    exec(code)  # palisade: ignore[PI-EXEC,PI-SHELL]
    exec(code)  # palisade: ignore

The comment goes on the sink line, or the line directly above it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# A bare `ignore` covers every rule; `ignore[A,B]` covers only those rules.
SUPPRESS_RE = re.compile(
    r"(?:#|//)\s*palisade\s*:\s*ignore(?:\[([^\]]*)\])?\s*(?:[-:]\s*(.*))?$",
    re.IGNORECASE,
)


@dataclass
class Suppression:
    line: int
    rules: frozenset[str] | None  # None means every rule
    reason: str = ""
    used: bool = False


def parse_suppressions(source: str) -> dict[int, Suppression]:
    """Map 1-based line number -> suppression declared on that line."""
    out: dict[int, Suppression] = {}
    for i, line in enumerate(source.splitlines(), start=1):
        m = SUPPRESS_RE.search(line)
        if not m:
            continue
        raw = (m.group(1) or "").strip()
        rules = frozenset(r.strip().upper() for r in raw.split(",") if r.strip()) if raw else None
        out[i] = Suppression(line=i, rules=rules, reason=(m.group(2) or "").strip())
    return out


def _match(rule_id: str, line: int, file_supps: dict[int, Suppression]) -> Suppression | None:
    """A finding is suppressed by a comment on its own line or the one above."""
    for candidate in (line, line - 1):
        s = file_supps.get(candidate)
        if s is not None and (s.rules is None or rule_id.upper() in s.rules):
            return s
    return None


def apply_suppressions(findings, by_file: dict[str, dict[int, Suppression]]):
    """Split findings into (kept, suppressed) and mark which comments fired."""
    kept, suppressed = [], []
    for f in findings:
        s = _match(f.rule_id, f.line, by_file.get(f.file, {}))
        if s is None:
            kept.append(f)
        else:
            s.used = True
            suppressed.append(
                {
                    "rule": f.rule_id,
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity,
                    "reason": s.reason,
                    "suppressed_at": s.line,
                }
            )
    return kept, suppressed


def stale_suppressions(by_file: dict[str, dict[int, Suppression]]) -> list[str]:
    """Comments that silenced nothing. Reported so they get cleaned up rather
    than lingering and masking a future finding."""
    out = []
    for path, supps in sorted(by_file.items()):
        for line in sorted(supps):
            if not supps[line].used:
                out.append(f"{path}:{line}")
    return out
