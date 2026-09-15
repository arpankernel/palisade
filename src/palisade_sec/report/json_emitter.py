"""Stable machine-readable JSON schema (UX-4).

Schema (v1):
{
  "schema_version": 1,
  "tool": "palisade-sec <version>",
  "summary": {"files_scanned": N, "high": N, "med": N, "low": N,
               "baseline_suppressed": N},
  "findings": [Finding.to_dict(), ...],   # sorted: severity, file, line, rule
  "skipped": ["file: reason", ...],
  "warnings": [...],
  "notes": [...]
}
"""

from __future__ import annotations

import json

from palisade_sec import __version__
from palisade_sec.engine import Finding

SCHEMA_VERSION = 1


def to_json(
    findings: list[Finding],
    files_scanned: int,
    skipped: list[str],
    warnings: list[str],
    notes: list[str],
    baseline_suppressed: int = 0,
) -> str:
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": f"palisade-sec {__version__}",
        "summary": {
            "files_scanned": files_scanned,
            "high": sum(1 for f in findings if f.severity == "high"),
            "med": sum(1 for f in findings if f.severity == "med"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "baseline_suppressed": baseline_suppressed,
        },
        "findings": [f.to_dict() for f in findings],
        "skipped": skipped,
        "warnings": warnings,
        "notes": notes,
    }
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"
