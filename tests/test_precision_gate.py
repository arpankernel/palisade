"""Enforce the fixture precision gate inside the test suite (not just CI), so
the deterministic detections - including the multi-agent PI-AGENT-HANDOFF
calibration - cannot silently regress."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_precision():
    spec = importlib.util.spec_from_file_location(
        "precision_harness", ROOT / "scripts" / "precision.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # register so @dataclass can resolve its module
    spec.loader.exec_module(mod)
    return mod


def test_fixture_corpus_precision_and_recall_are_perfect():
    precision = _load_precision()
    metrics, _threshold = precision.score_fixtures(ROOT / "corpus" / "manifest.yaml")
    assert metrics.precision == 1.0, metrics.detail
    assert metrics.recall == 1.0, metrics.detail


def test_multi_agent_fixtures_flag_exactly_the_vulnerable_files():
    # The calibration dir must flag PI-AGENT-HANDOFF on every vuln_*.py file
    # and stay silent on every safe_*.py wiring (safe handoff target,
    # constant input, safe crew, safe compiled-graph invoke).
    from palisade_sec.scanner import run_scan

    findings = run_scan(ROOT / "corpus" / "fixtures" / "agents").findings
    agent = sorted({f.sink.file for f in findings if f.rule_id == "PI-AGENT-HANDOFF"})
    vuln_files = sorted(p.name for p in (ROOT / "corpus" / "fixtures" / "agents").glob("vuln_*.py"))
    assert agent == vuln_files
