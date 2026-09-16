"""Offline regression for the Vanna CVE-2024-5565 shape (docs/proof-scans.md
item V1+V2+V3): library mode + a custom wrapper-LLM rule must flag the
exec(plotly_code...) sink, with the cosmetic sanitizer reported as
"unverified" rather than silencing the finding."""

from pathlib import Path

from palisade_sec.scanner import run_scan

FIXTURE = Path(__file__).parent / "fixtures" / "vanna_shape"
RULES = Path(__file__).parent / "fixtures" / "vanna_rules"


def test_vanna_shape_caught_with_library_mode_and_wrapper_rule():
    """The custom-wrapper-rule recipe works - and cross-rule dedup reports
    the vulnerability exactly once even though the builtin
    PI-FRAMEWORK-EXEC rule (since v0.3) matches the same chain."""
    res = run_scan(FIXTURE, rules_dir=str(RULES), assume_params_untrusted=True)
    assert len(res.findings) == 1, [(f.rule_id, f.sink.snippet) for f in res.findings]
    f = res.findings[0]
    assert f.rule_id in ("PI-VANNA-EXEC", "PI-FRAMEWORK-EXEC")
    # the CVE sink, with the full trace back to the library entry point
    assert "exec(plotly_code" in f.sink.snippet
    assert f.source.detail == "param:question"
    assert f.llm.detail.endswith("submit_prompt")
    # the cosmetic sanitizer downgrades to MED "risky" - it must NOT silence
    assert f.severity == "med" and f.risky
    assert [p.kind for p in f.partial_defenses] == ["unverified_sanitizer"]
    assert "_sanitize_plotly_code" in f.partial_defenses[0].pattern


def test_vanna_shape_silent_without_library_mode():
    """The wrapper rule alone is not enough: without library mode there is
    no untrusted source, so precision holds and nothing is flagged."""
    res = run_scan(FIXTURE, rules_dir=str(RULES))
    assert res.findings == []


def test_vanna_shape_caught_by_builtin_framework_rule():
    """Since v0.3 the builtin PI-FRAMEWORK-EXEC rule knows the
    *.submit_prompt wrapper signature, so library mode alone (no custom
    rule) catches the shape too."""
    res = run_scan(FIXTURE, assume_params_untrusted=True)
    assert [f.rule_id for f in res.findings] == ["PI-FRAMEWORK-EXEC"]
    f = res.findings[0]
    assert f.severity == "med" and f.risky
    assert [p.kind for p in f.partial_defenses] == ["unverified_sanitizer"]
