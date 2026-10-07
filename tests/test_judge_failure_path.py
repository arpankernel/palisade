"""The failure path of the judgment layer, which is the path least walked.

`JudgeError` documents that it never carries the API key or the raw prompt.
These tests hold it to that, and they cover the skip-and-report behaviour that
keeps one unredactable file from denying a whole audit.
"""

from __future__ import annotations

import json

import httpx
import pytest

from palisade_sec.judge.base import JudgeError
from palisade_sec.judge.guard import UnredactableStateError, guarded
from palisade_sec.judge.types import NoulAns, NoulQ

KEY = "sk-ant-api03-" + "K" * 40
SECRET_IN_SOURCE = "ghp_" + "S" * 36
QUESTIONS = [NoulQ(id="exploitable", instructions="is it exploitable?")]


# --------------------------------------------------------------------------
# no key, no snippet, in any error text
# --------------------------------------------------------------------------


def test_an_http_failure_names_no_key(monkeypatch) -> None:
    from palisade_sec.judge.anthropic import AnthropicBackend

    backend = AnthropicBackend(api_key=KEY, endpoint="https://example.invalid", model="m")

    def boom(*_a, **_k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", boom)
    monkeypatch.setattr(httpx.Client, "post", boom, raising=False)
    with pytest.raises(JudgeError) as exc:
        backend.ask({"source": "exec(x)"}, QUESTIONS)
    assert KEY not in str(exc.value)


def test_a_rejected_request_names_no_key_and_no_snippet(monkeypatch) -> None:
    """An endpoint can echo the request back in its error body. The reason
    must still be safe to print."""
    from palisade_sec.judge.anthropic import AnthropicBackend

    backend = AnthropicBackend(api_key=KEY, endpoint="https://example.invalid", model="m")
    echoed = json.dumps(
        {"error": {"message": f"bad request near exec({SECRET_IN_SOURCE}) with key {KEY}"}}
    )

    def rejected(*_a, **_k):
        return httpx.Response(
            400, text=echoed, request=httpx.Request("POST", "https://example.invalid")
        )

    monkeypatch.setattr(httpx.Client, "post", rejected, raising=False)
    monkeypatch.setattr(httpx, "post", rejected)
    with pytest.raises(JudgeError) as exc:
        backend.ask({"source": "exec(x)"}, QUESTIONS)
    assert KEY not in str(exc.value)


def test_the_unredactable_refusal_is_safe_to_print_and_log() -> None:
    from palisade_sec.judge.base import FakeBackend

    inner = FakeBackend(answers={"exploitable": NoulAns(value=0.5)})
    with pytest.raises(UnredactableStateError) as exc:
        guarded(inner).ask({"source": f"k='{SECRET_IN_SOURCE}'", "o": object()}, QUESTIONS)
    text = str(exc.value)
    assert SECRET_IN_SOURCE not in text
    assert "reported unjudged" in text


# --------------------------------------------------------------------------
# skip and report, not stop
# --------------------------------------------------------------------------


class _RefusingBackend:
    """Stands in for a guard that cannot clear one finding's evidence."""

    name = "refusing"
    verified = True

    def __init__(self, refuse_nth: int = 0):
        self.refuse_nth = refuse_nth
        self.seen = 0

    def ask(self, state, questions):
        from palisade_sec.judge.types import JudgeResult, ScoreAns

        current, self.seen = self.seen, self.seen + 1
        if current == self.refuse_nth:
            raise UnredactableStateError(("value of type Opaque at source",))
        return JudgeResult(
            answers={"exploitable": NoulAns(value=0.1), "severity": ScoreAns(score=1.0)},
            backend=self.name,
            verified=True,
        )


def _finding(line: int, snippet: str):
    """A taint finding shaped like the engine's real output."""
    from palisade_sec.engine.findings import Finding, TracePoint

    point = TracePoint(file="app.py", line=line, snippet=snippet)
    return Finding(
        rule_id="PI-EXEC",
        title="untrusted input reaches exec via the model",
        severity="high",
        confidence="HIGH",
        source=point,
        llm=point,
        sink=point,
    )


def test_one_unredactable_finding_does_not_deny_the_whole_audit() -> None:
    """A hard stop would let one poisoned file take out every other answer."""
    from palisade_sec.semantic.audit import UNJUDGED, audit_taint_exploitability

    out = audit_taint_exploitability(
        [_finding(1, "exec(x)"), _finding(2, "exec(y)")], _RefusingBackend(refuse_nth=0)
    )
    assert len(out) == 2
    assert out[0].decision == UNJUDGED
    assert out[1].decision != UNJUDGED


def test_an_unjudged_finding_carries_no_snippet() -> None:
    from palisade_sec.semantic.audit import UNJUDGED, audit_taint_exploitability

    out = audit_taint_exploitability(
        [_finding(7, f"key = '{SECRET_IN_SOURCE}'")], _RefusingBackend(refuse_nth=0)
    )
    assert out[0].decision == UNJUDGED
    blob = json.dumps(out[0].to_dict())
    assert SECRET_IN_SOURCE not in blob
    assert "app.py" in blob


def test_an_unjudged_finding_is_never_counted_as_a_pass() -> None:
    """The whole point of the status. An audit that skipped work must not
    read as an audit that came back clean."""
    from palisade_sec.semantic.audit import UNJUDGED, AuditReport, SemanticFinding, to_json

    def row(decision: str) -> SemanticFinding:
        return SemanticFinding(
            check="taint_exploitability",
            decision=decision,
            title="t",
            file="a.py",
            line=1,
            likelihood=0.0,
            impact=0.0,
            verified=False,
            backend="none",
        )

    report = AuditReport(findings=[row(UNJUDGED), row("pass")], tools_seen=0, files_scanned=1)
    data = json.loads(to_json(report))
    assert data["unjudged"] == 1
    assert data["complete"] is False


def test_a_clean_audit_still_reports_complete() -> None:
    from palisade_sec.semantic.audit import AuditReport, SemanticFinding, to_json

    row = SemanticFinding(
        check="taint_exploitability",
        decision="pass",
        title="t",
        file="a.py",
        line=1,
        likelihood=0.0,
        impact=0.0,
        verified=True,
        backend="fake",
    )
    data = json.loads(to_json(AuditReport(findings=[row], tools_seen=0, files_scanned=1)))
    assert data["unjudged"] == 0
    assert data["complete"] is True
