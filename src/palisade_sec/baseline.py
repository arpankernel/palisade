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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@dataclass
class BaselineDiff:
    new: list[Finding] = field(default_factory=list)
    known: list[Finding] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)  # fingerprints no longer seen
    warnings: list[str] = field(default_factory=list)


def load_fingerprints(path: Path) -> tuple[set[str], list[str]]:
    warnings: list[str] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        fps = set(doc.get("findings", {}).keys())
        return fps, warnings
    except FileNotFoundError:
        warnings.append(f"baseline file not found: {path} (treating all findings as new)")
    except (json.JSONDecodeError, OSError, AttributeError) as exc:
        warnings.append(f"invalid baseline file ignored: {path}: {exc}")
    return set(), warnings


def diff_against_baseline(findings: list[Finding], path: Path) -> BaselineDiff:
    diff = BaselineDiff()
    known_fps, diff_warnings = load_fingerprints(path)
    diff.warnings = diff_warnings
    seen: set[str] = set()
    for f in findings:
        seen.add(f.fingerprint)
        (diff.known if f.fingerprint in known_fps else diff.new).append(f)
    diff.stale = sorted(known_fps - seen)
    return diff
