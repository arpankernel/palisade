"""The JudgeBackend interface plus a test fake.

A backend takes grounded `state` and a batch of questions and returns typed
answers in ONE call. Nothing here reaches the network; the concrete adapters
(typesafe.py, openai_compatible.py) do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from palisade_sec.judge.types import Answer, JudgeResult, Question


class JudgeError(RuntimeError):
    """Any failure talking to a judgment backend: config, network, bad
    response, schema mismatch. Never carries the API key or the raw prompt."""


@runtime_checkable
class JudgeBackend(Protocol):
    name: str
    verified: bool  # True only for a calibrated backend (TypeSafe)

    def ask(self, state: object, questions: list[Question]) -> JudgeResult: ...


@dataclass
class FakeBackend:
    """Scripted backend for tests. Returns canned answers by question id and
    records the calls. `verified` is settable to exercise the no-BLOCK rule."""

    answers: dict[str, Answer]
    name: str = "fake"
    verified: bool = True
    calls: list[tuple[object, list[Question]]] = field(default_factory=list)

    def ask(self, state: object, questions: list[Question]) -> JudgeResult:
        self.calls.append((state, questions))
        picked = {q.id: self.answers[q.id] for q in questions if q.id in self.answers}
        return JudgeResult(answers=picked, backend=self.name, verified=self.verified)
