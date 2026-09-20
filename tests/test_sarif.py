"""SARIF 2.1.0 output: valid shape, severity mapping, locations, fingerprints -
what GitHub code scanning ingests."""

from __future__ import annotations

import json
from pathlib import Path

from palisade_sec.report import to_sarif
from palisade_sec.scanner import run_scan

ROOT = Path(__file__).resolve().parent.parent


def test_sarif_structure_on_example_app():
    findings = run_scan(ROOT / "examples" / "vulnerable-app").findings
    assert findings  # the example app has known findings
    doc = json.loads(to_sarif(findings))

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "palisade-sec"
    assert len(run["results"]) == len(findings)

    levels = {r["level"] for r in run["results"]}
    assert levels <= {"error", "warning", "note"}
    assert "error" in levels  # a HIGH finding maps to error

    rules = run["tool"]["driver"]["rules"]
    assert rules
    for r in run["results"]:
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert "palisade/v1" in r["partialFingerprints"]
        assert 0 <= r["ruleIndex"] < len(rules)
        assert r["ruleId"] == rules[r["ruleIndex"]]["id"]


def test_sarif_empty_is_valid():
    doc = json.loads(to_sarif([]))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def _uris(doc):
    return {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in doc["runs"][0]["results"]
    }


def test_sarif_base_uri_makes_paths_repo_relative():
    """Finding paths are relative to the scan target; GitHub resolves URIs from
    the repo root. base_uri prepends the scan base so a subdir scan is located
    correctly instead of at the repo root."""
    findings = run_scan(ROOT / "examples" / "vulnerable-app").findings
    assert findings
    bare = _uris(json.loads(to_sarif(findings)))
    prefixed = _uris(json.loads(to_sarif(findings, base_uri="examples/vulnerable-app")))
    assert all("/" not in u for u in bare)  # scan-relative, no dir
    assert prefixed == {f"examples/vulnerable-app/{u}" for u in bare}
    # "." and "" are no-ops (no leading ./)
    assert _uris(json.loads(to_sarif(findings, base_uri="."))) == bare
    assert _uris(json.loads(to_sarif(findings, base_uri=""))) == bare
