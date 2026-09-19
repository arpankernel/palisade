"""Backend-neutral question and answer types.

Checks build these questions; a backend answers them. The types mirror
TypeSafe's primitives (Noul = P(true), Choice = category, Score = severity) so
the calibrated backend maps to them directly, and the generic backend maps to
the same shapes with confidence dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Questions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NoulQ:
    """Yes/no. The answer is the probability the statement is true."""

    id: str
    instructions: str
    criteria: dict[str, str] | None = None  # {"true": ..., "false": ...}


@dataclass(frozen=True)
class ChoiceQ:
    """Pick one option. `criteria` maps option name -> description."""

    id: str
    instructions: str
    criteria: dict[str, str]


@dataclass(frozen=True)
class ScoreQ:
    """Rate on an ordered scale. `levels[i]` describes score i (0-based)."""

    id: str
    instructions: str
    levels: list[str]


Question = NoulQ | ChoiceQ | ScoreQ


# --------------------------------------------------------------------------
# Answers
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NoulAns:
    value: float  # P(true), 0..1


@dataclass(frozen=True)
class ChoiceAns:
    choice: str
    probabilities: dict[str, float] = field(default_factory=dict)
    confidence: float | None = None


@dataclass(frozen=True)
class ScoreAns:
    score: float  # probability-weighted level; may be fractional
    confidence: float | None = None


Answer = NoulAns | ChoiceAns | ScoreAns


@dataclass
class JudgeResult:
    """The answers for one batched call, tagged with which backend produced
    them and whether that backend is calibrated (`verified`)."""

    answers: dict[str, Answer]
    backend: str
    verified: bool
    usage: dict = field(default_factory=dict)

    def noul(self, qid: str) -> float:
        a = self._answer(qid)
        if not isinstance(a, NoulAns):
            raise self._wrong(qid, a, "noul")
        return a.value

    def score(self, qid: str) -> float:
        a = self._answer(qid)
        if not isinstance(a, ScoreAns):
            raise self._wrong(qid, a, "score")
        return a.score

    def choice(self, qid: str) -> str:
        a = self._answer(qid)
        if not isinstance(a, ChoiceAns):
            raise self._wrong(qid, a, "choice")
        return a.choice

    def _answer(self, qid: str) -> Answer:
        from palisade_sec.judge.base import JudgeError

        try:
            return self.answers[qid]
        except KeyError as exc:
            raise JudgeError(f"no answer for question {qid!r}") from exc

    @staticmethod
    def _wrong(qid: str, a: Answer, expected: str) -> Exception:
        from palisade_sec.judge.base import JudgeError

        return JudgeError(f"answer {qid!r} is {type(a).__name__}, expected {expected}")
