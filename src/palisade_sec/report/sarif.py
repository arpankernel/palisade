"""SARIF 2.1.0 emitter.

SARIF is the interchange format every AppSec pipeline speaks; emitting it lets a
five-line GitHub Action put Palisade findings straight into the Security tab as
code-scanning alerts. Severity maps high->error, med->warning, low->note. The
sink is the primary location; source and LLM boundary are related locations.
Fingerprints are line-shift resilient, so alerts don't churn on refactors.
"""

from __future__ import annotations

import json
import posixpath

from palisade_sec import __version__
from palisade_sec.engine import Finding, TracePoint

_LEVEL = {"high": "error", "med": "warning", "low": "note"}
_INFO_URI = "https://github.com/arpankernel/palisade"


def _uri(file: str, base_uri: str) -> str:
    """Make the artifact URI relative to the repository root.

    A finding's `file` is relative to the SCAN TARGET (scanning `src/` yields
    `foo.py`, not `src/foo.py`). GitHub code scanning resolves URIs against the
    repo root, so a subdirectory scan would place every alert at the wrong path.
    Prepending the scan base (relative to the repo root / cwd) fixes that."""
    if not base_uri or base_uri == ".":
        return file
    return posixpath.normpath(f"{base_uri}/{file}")


def _location(tp: TracePoint, role: str | None = None, base_uri: str = "") -> dict:
    loc: dict = {
        "physicalLocation": {
            "artifactLocation": {"uri": _uri(tp.file, base_uri)},
            "region": {"startLine": max(1, tp.line), "snippet": {"text": tp.snippet}},
        }
    }
    if role:
        loc["message"] = {"text": f"{role}: {tp.snippet}".strip()}
    return loc


def _message(f: Finding) -> str:
    parts = [f.title]
    if f.attack.strip():
        parts.append("Attack: " + f.attack.strip())
    if f.fix.strip():
        parts.append("Fix: " + f.fix.strip())
    return "\n\n".join(parts)


def to_sarif(findings: list[Finding], tool_version: str | None = None, base_uri: str = "") -> str:
    version = tool_version or __version__
    rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in rules:
            rule: dict = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            }
            if f.references:
                rule["helpUri"] = f.references[0]
            rules[f.rule_id] = rule
    rule_index = {rid: i for i, rid in enumerate(rules)}

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": _message(f)},
                "locations": [_location(f.sink, base_uri=base_uri)],
                "relatedLocations": [
                    _location(f.source, "source", base_uri=base_uri),
                    _location(f.llm, "llm", base_uri=base_uri),
                ],
                "partialFingerprints": {"palisade/v1": f.fingerprint},
            }
        )

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "palisade-sec",
                        "informationUri": _INFO_URI,
                        "version": version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
