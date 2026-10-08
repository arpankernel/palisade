"""The guard every judgment-layer call passes through.

Two properties are load-bearing and both are asserted here: no state reaches a
backend without passing redaction, and no payload reaches a backend without
the instruction boundary in front of the evidence.

The third group is the one that matters most in practice. `get_backend()` is
the only construction path, so a backend added later inherits the guard. If
that stops being true these tests go red.
"""

from __future__ import annotations

import pytest

from palisade_sec.judge.base import FakeBackend, JudgeError
from palisade_sec.judge.guard import (
    BOUNDARY,
    BOUNDARY_KEY,
    EVIDENCE_KEY,
    GuardedBackend,
    UnredactableStateError,
    guarded,
)
from palisade_sec.judge.types import NoulAns, NoulQ

SECRET = "sk-ant-api03-" + "Z" * 40
QUESTIONS = [NoulQ(id="q", instructions="is it exploitable?")]


def _fake() -> FakeBackend:
    return FakeBackend(answers={"q": NoulAns(value=0.5)})


def test_the_boundary_is_the_first_key_in_the_payload() -> None:
    """Ahead of any byte that came out of the analysed repository."""
    inner = _fake()
    guarded(inner).ask({"source": "exec(x)"}, QUESTIONS)
    sent, _ = inner.calls[0]
    assert list(sent.keys())[0] == BOUNDARY_KEY
    assert sent[BOUNDARY_KEY] == BOUNDARY


def test_the_boundary_names_the_files_an_attacker_would_use() -> None:
    for name in ("CLAUDE.md", "AGENTS.md", "README"):
        assert name in BOUNDARY
    assert "never instructions" in BOUNDARY


def test_the_evidence_is_nested_under_its_own_key() -> None:
    inner = _fake()
    guarded(inner).ask({"source": "exec(x)"}, QUESTIONS)
    sent, _ = inner.calls[0]
    assert sent[EVIDENCE_KEY] == {"source": "exec(x)"}


def test_a_secret_never_reaches_the_backend() -> None:
    inner = _fake()
    guarded(inner).ask({"source": f"k = '{SECRET}'"}, QUESTIONS)
    sent, _ = inner.calls[0]
    assert SECRET not in repr(sent)


def test_an_unredactable_state_is_not_sent_at_all() -> None:
    """Skip and report, not send and hope."""
    inner = _fake()
    with pytest.raises(UnredactableStateError):
        guarded(inner).ask({"thing": object()}, QUESTIONS)
    assert inner.calls == []


def test_the_refusal_is_a_judge_error_so_callers_catch_one_type() -> None:
    assert issubclass(UnredactableStateError, JudgeError)


def test_the_refusal_carries_no_value_only_types_and_paths() -> None:
    inner = _fake()
    with pytest.raises(UnredactableStateError) as exc:
        guarded(inner).ask({"source": f"k='{SECRET}'", "blob": object()}, QUESTIONS)
    text = str(exc.value)
    assert SECRET not in text
    assert "object" in text


def test_questions_pass_through_untouched() -> None:
    inner = _fake()
    guarded(inner).ask({"a": 1}, QUESTIONS)
    _, sent_questions = inner.calls[0]
    assert sent_questions == QUESTIONS


def test_name_and_verified_delegate_to_the_inner_backend() -> None:
    inner = FakeBackend(answers={}, name="inner", verified=True)
    g = guarded(inner)
    assert g.name == "inner"
    assert g.verified is True


def test_wrapping_is_idempotent() -> None:
    """A caller that wraps twice must not double-frame the payload."""
    once = guarded(_fake())
    assert guarded(once) is once


def test_double_wrapping_would_bury_the_boundary() -> None:
    """Shows why idempotence matters: without it, evidence nests twice and
    the boundary stops being adjacent to the code it governs."""
    inner = _fake()
    GuardedBackend(inner=GuardedBackend(inner=inner)).ask({"a": 1}, QUESTIONS)
    sent, _ = inner.calls[0]
    assert sent[EVIDENCE_KEY][BOUNDARY_KEY] == BOUNDARY  # the shape guarded() avoids


# --------------------------------------------------------------------------
# the chokepoint
# --------------------------------------------------------------------------


def test_get_backend_returns_a_guarded_backend(monkeypatch) -> None:
    """The one property that makes this unbypassable for future backends."""
    import palisade_sec.judge.config as config

    monkeypatch.setattr(config, "_construct_backend", _fake)
    assert isinstance(config.get_backend(), GuardedBackend)


def test_every_backend_branch_goes_through_the_single_wrap() -> None:
    """`get_backend` must not grow a return path of its own. If it does, a
    branch can be added that skips the guard."""
    import inspect

    import palisade_sec.judge.config as config

    src = inspect.getsource(config.get_backend)
    assert src.count("return") == 1
    assert "guarded(" in src


def test_the_wrapper_does_not_hide_the_backend_from_describe() -> None:
    """`describe()` reads the model and endpoint off the backend by getattr and
    prints "?" when they are missing. Wrapping hid both, so the CLI banner lost
    them: a guard should not take information out of a user-facing line."""
    from palisade_sec.judge.config import describe

    class Backend(FakeBackend):
        endpoint = "https://api.example.invalid"
        model = "a-model-id"

    line = describe(guarded(Backend(answers={})))
    assert "a-model-id" in line
    assert "https://api.example.invalid" in line
    assert "?" not in line
