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
