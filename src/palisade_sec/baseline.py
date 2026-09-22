"""Baseline: adopt Palisade on an imperfect codebase without a wall of
pre-existing failures. CI then fails only on NEW findings.

Fingerprints are line-independent (see Finding.fingerprint), the JSON file is
sorted and deterministic (BL-2), stale entries are ignored (BL-3).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from palisade_sec import __version__
from palisade_sec.engine import Finding
from palisade_sec.safe_io import write_output

DEFAULT_BASELINE = ".palisade/baseline.json"
SCHEMA_VERSION = 1


def write_baseline(findings: list[Finding], path: Path) -> None:
    entries: dict[str, dict[str, Any]] = {}
    for f in findings:
        fp = f.fingerprint
        if fp in entries:
            entries[fp]["count"] += f.count
        else:
            entries[fp] = {
                "rule": f.rule_id,
                "file": f.file,
                "severity": f.severity,
                "count": f.count,
            }
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": f"palisade-sec {__version__}",
        "findings": {fp: entries[fp] for fp in sorted(entries)},
    }
    # Symlink-safe: `.palisade` or the file itself may be a link planted by
    # the scanned repository.
    write_output(path, json.dumps(doc, indent=2, sort_keys=True) + "\n")


@dataclass
class BaselineDiff:
    new: list[Finding] = field(default_factory=list)
    known: list[Finding] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)  # fingerprints no longer seen
    warnings: list[str] = field(default_factory=list)


def load_fingerprints(path: Path) -> tuple[dict[str, int | None], list[str]]:
    """Known fingerprints mapped to how many occurrences were accepted (None
    for a baseline entry without a count)."""
    warnings: list[str] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        entries = doc.get("findings", {}) if isinstance(doc, dict) else None
        if not isinstance(entries, dict):
            raise ValueError("expected an object with a 'findings' mapping")
        known: dict[str, int | None] = {}
        for fp, entry in entries.items():
            count = entry.get("count") if isinstance(entry, dict) else None
            known[fp] = count if isinstance(count, int) else None
        return known, warnings
    except FileNotFoundError:
        warnings.append(f"baseline file not found: {path} (treating all findings as new)")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, OSError) as exc:
        reason = (
            "not valid JSON"
            if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError))
            else str(exc)
        )
        warnings.append(
            f"invalid baseline file ignored: {path} ({reason}); treating all findings as new"
        )
    return {}, warnings


def diff_against_baseline(findings: list[Finding], path: Path) -> BaselineDiff:
    diff = BaselineDiff()
    known, diff_warnings = load_fingerprints(path)
    diff.warnings = diff_warnings
    # Occurrences per fingerprint now. A fingerprint is line-independent, so a
    # copy-pasted vulnerable block collapses into the SAME fingerprint as the
    # accepted original and only raises its count. Comparing counts is what
    # stops a known-bad pattern from being duplicated through the gate.
    current: dict[str, int] = {}
    for f in findings:
        current[f.fingerprint] = current.get(f.fingerprint, 0) + f.count
    for f in findings:
        fp = f.fingerprint
        accepted = known.get(fp, 0) if fp in known else 0
        if fp not in known:
            diff.new.append(f)
        elif accepted is not None and current[fp] > accepted:
            diff.new.append(f)
            diff.warnings.append(
                f"{f.rule_id} at {f.file}: {current[fp] - accepted} new occurrence(s) of a "
                f"baselined finding ({accepted} accepted, {current[fp]} now)"
            )
        else:
            diff.known.append(f)
    diff.stale = sorted(set(known) - set(current))
    return diff
