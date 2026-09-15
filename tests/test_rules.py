"""Rule loading and schema validation."""

from palisade_sec.rules import load_rules
from palisade_sec.rules.schema import PatternSpec, match_lenient, match_strict


def test_builtin_rules_load():
    result = load_rules()
    ids = {r.id for r in result.rules}
    assert {"PI-EXEC", "PI-SHELL", "PI-SQL"} <= ids
    assert result.warnings == []
    for rule in result.rules:
        assert rule.severity in ("high", "med", "low")
        assert rule.llm_signatures and rule.sinks
        assert rule.fix.strip(), f"{rule.id}: every rule must teach a fix"


def test_user_rules_dir_extends(tmp_path):
    (tmp_path / "custom.yaml").write_text(
        """
id: PI-CUSTOM
title: Custom sink
severity: high
description: test
llm_signatures:
  - kind: call
    patterns: ["chat.completions.create"]
sinks:
  - kind: call
    patterns: ["dangerous_thing"]
fix: don't
"""
    )
    result = load_rules(str(tmp_path))
    assert "PI-CUSTOM" in {r.id for r in result.rules}


def test_invalid_rule_skipped_with_warning(tmp_path):
    (tmp_path / "bad.yaml").write_text("id: X\nseverity: catastrophic\n")
    result = load_rules(str(tmp_path))
    assert any("bad.yaml" in w for w in result.warnings)
    assert {"PI-EXEC", "PI-SHELL", "PI-SQL"} <= {r.id for r in result.rules}


def test_match_strict_semantics():
    assert match_strict("exec", "exec")
    assert not match_strict("obj.exec", "exec")  # single-segment = exact only
    assert match_strict("client.chat.completions.create", "chat.completions.create")
    assert match_strict("flask.request.json", "request.json")
    assert not match_strict("subprocess.run", "chain.run")
    assert match_strict("cur.execute", "*.execute")
    assert not match_strict("execute", "*.execute")  # bare name doesn't match


def test_match_lenient_semantics():
    specs = [PatternSpec(kind="call", patterns=["denylist", "blocked", "confirm"])]
    assert match_lenient("guards.is_blocked_code", specs)
    assert match_lenient("COMMAND_DENYLIST", specs)
    assert not match_lenient("run_command", specs)
