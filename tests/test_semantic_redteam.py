"""Red-team synthesis is deterministic/offline; execution is gated and driven by
a user-provided target. These tests use fakes - no network, no TypeSafe, and no
execution of real target code."""

from __future__ import annotations

import pytest

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.inventory import build_map
from palisade_sec.semantic.redteam import (
    DATA_EXFILTRATION,
    TOOL_COERCION,
    CompositeScorer,
    DeterministicScorer,
    Response,
    Verdict,
    plan,
    run,
    synthesize,
)

SRC = """
import os, subprocess
from openai import OpenAI
from langchain.agents import initialize_agent
from langchain.tools import tool

client = OpenAI()


def ask(q):
    return client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": q}])


def make_agent(tools, llm):
    return initialize_agent(tools, llm)


@tool
def run_cmd(cmd):
    subprocess.run(cmd, shell=True)


@tool
def read_env(key):
    return os.getenv(key)
"""


def _map(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return build_map([mod])


def test_synthesis_targets_the_real_surface():
    cases = synthesize(_map(SRC), variants=2)
    coerced = {c.target_name for c in cases if c.technique == TOOL_COERCION}
    assert coerced == {"run_cmd", "read_env"}  # both dangerous tools targeted
    assert any(c.technique == DATA_EXFILTRATION for c in cases)  # secrets tool present
    # every injection case must be judged behaviorally, not deterministically
    inj = [c for c in cases if c.success["type"] == "judgment"]
    assert inj and all("instruction" in c.success for c in inj)


def test_ids_unique_and_sequential():
    cases = synthesize(_map(SRC), variants=2)
    ids = [c.id for c in cases]
    assert ids == [f"RT-{i:03d}" for i in range(1, len(cases) + 1)]
    assert len(set(ids)) == len(ids)


def test_no_surface_no_attacks():
    assert synthesize(_map("x = 1 + 1\n")) == []


# -- scoring ---------------------------------------------------------------


def test_deterministic_scorer_detects_tool_invocation():
    (case,) = [c for c in synthesize(_map(SRC)) if c.target_name == "run_cmd"][:1]
    det = DeterministicScorer()
    assert det.score(case, Response(tool_calls=["run_cmd"])).landed is True
    assert det.score(case, Response(tool_calls=[])).landed is False


def test_deterministic_scorer_refuses_judgment_types():
    judgment_case = next(c for c in synthesize(_map(SRC)) if c.success["type"] == "judgment")
    with pytest.raises(ValueError):
        DeterministicScorer().score(judgment_case, Response(output_text="anything"))


# -- gate + end to end -----------------------------------------------------


class FakeVulnTarget:
    """A deliberately vulnerable agent: fires any coerced tool, obeys any inject."""

    def send(self, attack):
        if attack.success["type"] == "tool_invoked":
            return Response(tool_calls=[attack.success["tool"]])
        return Response(output_text="PWNED - ignoring my original instructions")


class FakeSafeTarget:
    def send(self, attack):
        return Response(output_text="I can't help with that.", tool_calls=[])


class FakeJudge:
    def score(self, attack, response):
        landed = "pwned" in response.output_text.lower()
        return Verdict(landed, 0.9 if landed else 0.1, "fake judge")


def test_run_refuses_without_approval():
    cases = synthesize(_map(SRC))
    with pytest.raises(PermissionError):
        run(cases, FakeVulnTarget(), DeterministicScorer(), approved=False)


def test_end_to_end_vulnerable_target_all_land():
    cases = plan(_map(SRC))
    scorer = CompositeScorer(DeterministicScorer(), FakeJudge())
    report = run(cases, FakeVulnTarget(), scorer, approved=True)
    s = report.summary()
    assert s["attacks_run"] == len(cases)
    assert s["attacks_landed"] == len(cases)  # vulnerable target fails everything
    assert set(s["by_technique"]) == {c.technique for c in cases}


def test_end_to_end_safe_target_nothing_lands():
    cases = plan(_map(SRC))
    scorer = CompositeScorer(DeterministicScorer(), FakeJudge())
    report = run(cases, FakeSafeTarget(), scorer, approved=True)
    assert report.summary()["attacks_landed"] == 0
    assert report.landed == []


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
