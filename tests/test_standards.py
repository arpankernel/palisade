"""Every finding maps to the standards security teams file under: CWE (incl.
the AI-specific CWE-1426/1427) and the OWASP Top 10 for LLM Applications
2025, surfaced in SARIF the way GitHub code scanning reads them."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from palisade_sec.cli import app
from palisade_sec.rules.loader import load_rules
from palisade_sec.standards import CWE_NAMES, OWASP_LLM_2025, sarif_cwe_tag, sarif_owasp_tag

runner = CliRunner()
ROOT = Path(__file__).parent.parent
RULES = load_rules(None).rules


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_builtin_rule_is_mapped(rule):
    assert "CWE-1427" in rule.cwe, "every rule is prompt injection (CWE-1427)"
    assert "LLM01:2025" in rule.owasp_llm
    assert rule.security_severity is not None
    for c in rule.cwe:
        assert c in CWE_NAMES, f"{rule.id}: {c} is not in the verified CWE table"
    for o in rule.owasp_llm:
        assert o in OWASP_LLM_2025, f"{rule.id}: {o} is not in the verified OWASP table"
    # the generic, version-less OWASP page is replaced by the 2025 category pages
    assert not any("www-project-top-10-for-large" in ref for ref in rule.references)


def test_severity_scores_match_github_buckets():
    by_id = {r.id: r.security_severity for r in RULES}
    assert by_id["PI-EXEC"] >= 9.0 and by_id["PI-SHELL"] >= 9.0  # critical
    assert 7.0 <= by_id["PI-SQL"] < 9.0  # high
    assert 4.0 <= by_id["PI-HTTP"] < 7.0  # medium: advisory, never gates CI


def test_custom_rule_with_a_malformed_mapping_is_rejected(tmp_path):
    rule = (ROOT / "src/palisade_sec/rules/pi-exec.yaml").read_text()
    bad = rule.replace("id: PI-EXEC", "id: MY-RULE").replace("cwe: [CWE-94", 'cwe: ["cwe94"')
    (tmp_path / "mine.yaml").write_text(bad)
    res = load_rules(str(tmp_path))
    assert any("mine.yaml" in w and "CWE-94" in w for w in res.warnings), res.warnings


def test_custom_rule_without_a_mapping_still_loads(tmp_path):
    lines = (ROOT / "src/palisade_sec/rules/pi-exec.yaml").read_text().splitlines()
    kept = [ln for ln in lines if not ln.startswith(("cwe:", "owasp_llm:", "security_severity:"))]
    (tmp_path / "old.yaml").write_text("\n".join(kept).replace("id: PI-EXEC", "id: OLD-RULE"))
    res = load_rules(str(tmp_path))
    assert any(r.id == "OLD-RULE" for r in res.rules), res.warnings


def test_sarif_carries_github_tags_and_security_severity():
    doc = json.loads(
        runner.invoke(app, ["scan", str(ROOT / "examples/support-bot"), "--sarif"]).stdout
    )
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    props = rules["PI-SQL"]["properties"]
    assert "external/cwe/cwe-089" in props["tags"]
    assert "external/cwe/cwe-1427" in props["tags"]
    assert "external/owasp-llm/llm01-2025" in props["tags"]
    assert props["security-severity"] == "8.8"
    assert rules["PI-EXEC"]["helpUri"].startswith("https://genai.owasp.org/llmrisk/")


def test_json_findings_carry_the_mapping():
    doc = json.loads(
        runner.invoke(app, ["scan", str(ROOT / "examples/support-bot"), "--json"]).stdout
    )
    f = next(x for x in doc["findings"] if x["rule"] == "PI-SHELL")
    assert f["cwe"] == ["CWE-78", "CWE-1426", "CWE-1427"]
    assert f["owasp_llm"] == ["LLM01:2025", "LLM05:2025"]


def test_agent_handoff_findings_are_mapped():
    res = runner.invoke(app, ["scan", str(ROOT / "corpus/fixtures/agents"), "--json"])
    handoffs = [f for f in json.loads(res.stdout)["findings"] if f["rule"] == "PI-AGENT-HANDOFF"]
    assert handoffs, "fixture should produce a handoff finding"
    assert handoffs[0]["cwe"] == ["CWE-441", "CWE-1427"]
    assert handoffs[0]["owasp_llm"] == ["LLM01:2025", "LLM06:2025"]


def test_tag_formats():
    assert sarif_cwe_tag("CWE-78") == "external/cwe/cwe-078"
    assert sarif_cwe_tag("CWE-1426") == "external/cwe/cwe-1426"
    assert sarif_owasp_tag("LLM05:2025") == "external/owasp-llm/llm05-2025"
