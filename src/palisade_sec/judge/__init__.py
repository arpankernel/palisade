"""The judgment layer: turn IR-verified facts into typed answers.

This package is NOT imported by the offline core (scan, map, baseline,
deterministic fix). It is reached only by bring-your-own-endpoint commands
(audit, review, redteam execution) and needs an endpoint + key configured in
`.env`. Two adapters sit behind one `JudgeBackend` interface:

- TypeSafe (default, recommended): calibrated typed answers. `verified=True`.
- Generic OpenAI-compatible: a strict-JSON prompt validated against a schema.
  Results are labelled best-effort/unverified and can never BLOCK on judgment
  alone.

Every question asked here is grounded in a fact the static analyzer verified;
the caller supplies that fact as `state`.
"""

from palisade_sec.judge.base import FakeBackend, JudgeBackend, JudgeError
from palisade_sec.judge.types import (
    Answer,
    ChoiceAns,
    ChoiceQ,
    JudgeResult,
    NoulAns,
    NoulQ,
    Question,
    ScoreAns,
    ScoreQ,
)

__all__ = [
    "Answer",
    "ChoiceAns",
    "ChoiceQ",
    "FakeBackend",
    "JudgeBackend",
    "JudgeError",
    "JudgeResult",
    "NoulAns",
    "NoulQ",
    "Question",
    "ScoreAns",
    "ScoreQ",
]
