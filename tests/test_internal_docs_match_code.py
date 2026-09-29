"""`docs/typesafe-integration.md` is the judgment layer's spec, and it drifted.

It claimed "1 of ~9 checks + 5 taint rules" for months after the second check
and the sixth rule shipped, listed a 4-module layout that had grown to 13, and
told readers to install an extra (`[semantic]`) and set a key
(`TYPESAFE_API_KEY`) that are no longer the only ones. Nothing caught it,
because prose has no tests.

These are the few claims in that document that are countable from the code.
Pinning only those keeps the test honest: a spec is allowed to describe things
that do not exist yet, so this asserts the *shipped* counts are stated
correctly, not that every row is built.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "typesafe-integration.md"
SRC = ROOT / "src" / "palisade_sec"


@pytest.fixture(scope="module")
def doc() -> str:
    """The prose as one long line. Markdown is hard-wrapped at 80 columns, so a
    phrase this test cares about is routinely split across a newline - the same
    trap that made the CLI output tests brittle."""
    return " ".join(DOC.read_text(encoding="utf-8").split())


def _taint_rule_count() -> int:
    """The 5 YAML rules plus PI-AGENT-HANDOFF, which lives in code."""
    yaml_rules = {
        m.group(1)
        for path in (SRC / "rules").glob("*.yaml")
        for m in [re.search(r"^id:\s*(\S+)", path.read_text(encoding="utf-8"), re.M)]
        if m
    }
    agents = (SRC / "semantic" / "agents" / "findings.py").read_text(encoding="utf-8")
    code_rules = set(re.findall(r'^RULE_ID\s*=\s*"([^"]+)"', agents, re.M))
    return len(yaml_rules | code_rules)


def _shipped_check_count() -> int:
    """Judged checks `audit` actually runs, counted from its orchestrator."""
    audit = (SRC / "semantic" / "audit.py").read_text(encoding="utf-8")
    return len(re.findall(r"^def audit_(\w+)\(", audit, re.M))


def test_the_counters_are_not_vacuous() -> None:
    """If these helpers silently returned 0, every assertion below would pass
    for the wrong reason."""
    assert _taint_rule_count() == 6, _taint_rule_count()
    assert _shipped_check_count() == 2, _shipped_check_count()


def test_doc_states_the_real_taint_rule_count(doc: str) -> None:
    n = _taint_rule_count()
    assert f"**{n}** deterministic taint" in doc or f"+ **{n}** taint rules" in doc, (
        f"there are {n} taint rules; the doc does not say so"
    )
    assert "5 taint rules" not in doc, "stale count: there are 6 taint rules"


def test_doc_states_the_real_shipped_check_count(doc: str) -> None:
    n = _shipped_check_count()
    assert f"**{n} of ~9**" in doc, f"`audit` runs {n} checks; the doc does not say so"
    assert "1 of ~9" not in doc, "stale count: a second judged check shipped in v0.5.0"


def test_doc_names_the_extra_that_actually_exists(doc: str) -> None:
    """`[semantic]` is only an alias now; telling a reader to install it as *the*
    name sends them to the wrong place in every other doc."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "\njudge = [" in pyproject, "the [judge] extra is gone; this test needs updating"
    assert "`[judge]`" in doc, "the doc must name the [judge] extra"
    assert "pip install 'palisade-sec[judge]'" in doc


def test_doc_mentions_connect_llm(doc: str) -> None:
    """0.6.0 made `connect llm` the way a key gets set. A spec that only
    mentions env vars and .env describes the previous release."""
    assert "palisade-sec connect llm" in doc


@pytest.mark.parametrize(
    "backend",
    ["typesafe", "anthropic", "openai_compatible"],
)
def test_doc_covers_every_shipped_backend(doc: str, backend: str) -> None:
    assert (SRC / "judge" / f"{backend}.py").is_file(), f"{backend} backend is gone"
    assert backend in doc, f"{backend} backend ships but the doc never names it"


def test_doc_does_not_claim_policy_files_load(doc: str) -> None:
    """The spec shows a .palisade/policy.yaml. No reader exists, so the doc has
    to say so — this is the gap most likely to mislead someone adopting it."""
    policy = (SRC / "semantic" / "policy.py").read_text(encoding="utf-8")
    loads_files = bool(re.search(r"def load_policy|policy\.yaml[\"']|read_text", policy))
    if loads_files:
        pytest.skip("policy file loading now exists; update the doc and drop this test")
    assert "does not load yet" in doc, (
        "policy.py still has no file reader; the doc must not imply the YAML works"
    )


def test_doc_carries_the_recall_number(doc: str) -> None:
    """The layer's honest weak point. A capability doc that lists 9 checks and
    omits recall 0.200 oversells."""
    assert "recall 0.200" in doc or "precision 1.000, recall 0.200" in doc
