"""AUDIT routing with a FakeBackend - no endpoint, no network. Locks the two
checks' decision matrices, the unverified-no-BLOCK rule, and the cost gate."""

from __future__ import annotations

import pytest

from palisade_sec.engine import Finding, TracePoint
from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.judge.base import FakeBackend
from palisade_sec.judge.types import NoulAns, ScoreAns
from palisade_sec.semantic.audit import (
    audit_excessive_agency,
    audit_taint_exploitability,
    decide,
    decide_exploit,
)
from palisade_sec.semantic.exploitability import ExploitJudgment
from palisade_sec.semantic.judge import Judgment
from palisade_sec.semantic.policy import CheckPolicy, default_policy


def _lower(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return [mod]


def _agency_answers(irreversible: float, gated: float, harm: float) -> dict:
    return {"irreversible": NoulAns(irreversible), "gated": NoulAns(gated), "harm": ScoreAns(harm)}


def _exploit_answers(exploitable: float, severity: float) -> dict:
    return {"exploitable": NoulAns(exploitable), "severity": ScoreAns(severity)}


def _finding(severity="high", confidence="HIGH", rule="PI-EXEC") -> Finding:
    tp = TracePoint(file="app.py", line=10, snippet="exec(code)")
    return Finding(
        rule_id=rule,
        title="t",
        severity=severity,
        confidence=confidence,
        source=TracePoint("app.py", 1, "q = request.json['q']"),
        llm=TracePoint("app.py", 5, "client.chat.completions.create(...)"),
        sink=tp,
    )


# -- excessive agency -------------------------------------------------------


def test_agency_blocks_and_unverified_downgrades():
    assert decide(CheckPolicy(), Judgment(0.95, 0.02, 3))[0] == "block"
    d, why = decide(CheckPolicy(), Judgment(0.95, 0.02, 3), verified=False)
    assert d == "review" and "unverified" in why


def test_agency_cost_gate_and_fields():
    src = (
        "import shutil\n@tool\ndef wipe(p):\n    shutil.rmtree(p)\n"
        "@tool\ndef add(a, b):\n    return a + b\n"
    )
    backend = FakeBackend(answers=_agency_answers(0.97, 0.01, 3.0))
    findings = audit_excessive_agency(_lower(src), backend, default_policy())
    assert [f.title for f in findings] == ["wipe"]  # pure `add` never judged
    assert len(backend.calls) == 1
    f = findings[0]
    assert f.check == "excessive_agency"
    assert f.decision == "block"
    assert f.detail["capabilities"] == ["file_write"]


# -- taint exploitability ---------------------------------------------------


def test_exploit_decision_matrix():
    pol = CheckPolicy(action_threshold=0.6, review_threshold=0.3, severity_block=2)
    assert decide_exploit(pol, ExploitJudgment(0.9, 3))[0] == "block"
    assert decide_exploit(pol, ExploitJudgment(0.9, 1))[0] == "review"
    assert decide_exploit(pol, ExploitJudgment(0.4, 0))[0] == "review"
    assert decide_exploit(pol, ExploitJudgment(0.1, 0))[0] == "pass"
    d, why = decide_exploit(pol, ExploitJudgment(0.9, 3), verified=False)
    assert d == "review" and "unverified" in why


def test_exploit_verified_refines_risk():
    backend = FakeBackend(answers=_exploit_answers(0.2, 1.0))  # judged low
    findings = audit_taint_exploitability([_finding()], backend, default_policy())
    f = findings[0]
    assert f.verified is True
    # verified backend is trusted to lower a HIGH/HIGH path
    assert f.likelihood == pytest.approx(0.2)
    assert f.impact == pytest.approx(1 / 3, abs=1e-3)


def test_exploit_unverified_does_not_move_risk():
    backend = FakeBackend(answers=_exploit_answers(0.05, 0.0), verified=False)
    findings = audit_taint_exploitability([_finding()], backend, default_policy())
    f = findings[0]
    # unverified judgment is advisory only: static HIGH/HIGH risk stands
    assert f.likelihood == pytest.approx(0.9)
    assert f.impact == pytest.approx(1.0)
    assert f.detail["exploitable"] == pytest.approx(0.05)  # shown as advisory


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
