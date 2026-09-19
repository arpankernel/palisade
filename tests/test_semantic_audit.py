"""AUDIT routing is tested with a FakeJudge - no TypeSafe, no network. This
locks the policy decision matrix and the cost gate (pure tools are never
judged)."""

from __future__ import annotations

import pytest

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.audit import audit_excessive_agency, decide
from palisade_sec.semantic.judge import Judgment
from palisade_sec.semantic.policy import CheckPolicy, default_policy


def _lower(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return [mod]


class FakeJudge:
    """Returns canned judgments; asserts it is never asked about a tool with
    no capability (the cost gate would be broken otherwise)."""

    def __init__(self, table: dict[str, Judgment]):
        self.table = table
        self.judged: list[str] = []

    def judge_excessive_agency(self, artifact, policy):
        self.judged.append(artifact.name)
        assert artifact.name in self.table, f"judged an unexpected tool: {artifact.name}"
        return self.table[artifact.name]


# -- decide() matrix --------------------------------------------------------


def test_decide_blocks_ungated_irreversible_high_harm():
    pol = CheckPolicy()
    d, _ = decide(pol, Judgment(irreversible=0.95, gated=0.02, harm=3))
    assert d == "block"


def test_decide_reviews_ungated_irreversible_low_harm():
    pol = CheckPolicy()
    d, _ = decide(pol, Judgment(irreversible=0.9, gated=0.0, harm=1))
    assert d == "review"


def test_decide_passes_when_gated():
    pol = CheckPolicy()
    d, why = decide(pol, Judgment(irreversible=0.99, gated=0.95, harm=3))
    assert d == "pass"
    assert "gate" in why


def test_decide_passes_low_irreversible():
    pol = CheckPolicy()
    d, _ = decide(pol, Judgment(irreversible=0.1, gated=0.0, harm=0))
    assert d == "pass"


def test_policy_tightening_turns_review_into_block():
    strict = CheckPolicy(severity_block=1)
    d, _ = decide(strict, Judgment(irreversible=0.9, gated=0.0, harm=1))
    assert d == "block"


# -- end to end with FakeJudge ---------------------------------------------

TOOLS_SRC = """
import os
import shutil
import requests

@tool
def delete_account(user_id: str):
    shutil.rmtree(f"/data/{user_id}")

@tool
def fetch_weather(city: str):
    return requests.get(f"https://api/{city}")

@tool
def refund(order_id: str):
    os.system(f"refund {order_id}")

@tool
def add(a, b):
    return a + b
"""


def test_audit_routes_each_tool_and_gates_cost():
    judge = FakeJudge(
        {
            "delete_account": Judgment(irreversible=0.97, gated=0.01, harm=3),
            "fetch_weather": Judgment(irreversible=0.05, gated=0.0, harm=0),
            "refund": Judgment(irreversible=0.9, gated=0.92, harm=3),  # gated -> pass
        }
    )
    findings = audit_excessive_agency(_lower(TOOLS_SRC), judge, default_policy())
    by_name = {f.tool_name: f.decision for f in findings}

    assert by_name["delete_account"] == "block"
    assert by_name["fetch_weather"] == "pass"
    assert by_name["refund"] == "pass"
    # cost gate: the pure `add` tool has no capability and is never judged
    assert "add" not in judge.judged
    assert "add" not in by_name


def test_findings_carry_grounded_evidence():
    judge = FakeJudge({"delete_account": Judgment(0.97, 0.01, 3)})
    src = "import shutil\n@tool\ndef delete_account(u):\n    shutil.rmtree(u)\n"
    findings = audit_excessive_agency(_lower(src), judge)
    assert len(findings) == 1
    f = findings[0]
    assert f.capabilities == ["file_write"]
    assert any("shutil.rmtree" in e for e in f.evidence)


def test_judgment_positional_construction():
    # Judgment is used positionally in tests; keep the field order stable.
    j = Judgment(0.5, 0.5, 2)
    assert (j.irreversible, j.gated, j.harm) == (0.5, 0.5, 2)


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
