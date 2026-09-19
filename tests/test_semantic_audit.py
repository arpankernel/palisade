"""AUDIT routing is tested with a FakeBackend - no endpoint, no network. This
locks the policy decision matrix, the unverified-no-BLOCK rule, and the cost
gate (pure tools are never judged)."""

from __future__ import annotations

import pytest

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.judge.base import FakeBackend
from palisade_sec.judge.types import NoulAns, ScoreAns
from palisade_sec.semantic.audit import audit_excessive_agency, decide
from palisade_sec.semantic.judge import Judgment
from palisade_sec.semantic.policy import CheckPolicy, default_policy


def _lower(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return [mod]


def _answers(irreversible: float, gated: float, harm: float) -> dict:
    return {
        "irreversible": NoulAns(irreversible),
        "gated": NoulAns(gated),
        "harm": ScoreAns(harm),
    }


# -- decide() matrix --------------------------------------------------------


def test_decide_blocks_ungated_irreversible_high_harm():
    d, _ = decide(CheckPolicy(), Judgment(irreversible=0.95, gated=0.02, harm=3))
    assert d == "block"


def test_decide_reviews_ungated_irreversible_low_harm():
    d, _ = decide(CheckPolicy(), Judgment(irreversible=0.9, gated=0.0, harm=1))
    assert d == "review"


def test_decide_passes_when_gated():
    d, why = decide(CheckPolicy(), Judgment(irreversible=0.99, gated=0.95, harm=3))
    assert d == "pass"
    assert "gate" in why


def test_unverified_backend_never_blocks():
    d, why = decide(CheckPolicy(), Judgment(irreversible=0.99, gated=0.0, harm=3), verified=False)
    assert d == "review"
    assert "unverified" in why


def test_verified_backend_still_blocks():
    d, _ = decide(CheckPolicy(), Judgment(irreversible=0.99, gated=0.0, harm=3), verified=True)
    assert d == "block"


def test_policy_tightening_turns_review_into_block():
    d, _ = decide(CheckPolicy(severity_block=1), Judgment(irreversible=0.9, gated=0.0, harm=1))
    assert d == "block"


# -- end to end with FakeBackend -------------------------------------------

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
    # One scripted answer set; every judged tool gets the same answers here,
    # so assert on decisions and on which tools were judged.
    backend = FakeBackend(answers=_answers(0.97, 0.01, 3.0))
    findings = audit_excessive_agency(_lower(TOOLS_SRC), backend, default_policy())
    judged = {f.tool_name for f in findings}

    assert judged == {"delete_account", "fetch_weather", "refund"}
    assert "add" not in judged  # pure tool, no capability -> never judged
    assert len(backend.calls) == 3  # cost gate: one call per judgeable tool
    assert all(f.decision == "block" for f in findings)  # verified backend, high harm


def test_audit_labels_unverified_backend():
    backend = FakeBackend(
        answers=_answers(0.97, 0.01, 3.0), name="openai_compatible", verified=False
    )
    src = "import shutil\n@tool\ndef wipe(p):\n    shutil.rmtree(p)\n"
    findings = audit_excessive_agency(_lower(src), backend)
    assert len(findings) == 1
    f = findings[0]
    assert f.verified is False
    assert f.decision == "review"  # downgraded from block
    assert f.backend == "openai_compatible"


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
