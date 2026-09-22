"""TypeSafe adapter (default, recommended).

Talks the TypeSafe System One HTTP API directly, so the endpoint stays
env-configurable. Returns calibrated typed answers, so `verified=True`.

API: POST {endpoint}/v1/systemone , Bearer auth,
     body {state, model, questions:{id:{type,instructions,criteria}}},
     response {answers:{id:{type, noul|choice|score, ...}}, usage}.
See https://docs.typesafe.ai/api.md
"""

from __future__ import annotations

import httpx

from palisade_sec.judge._http import post_json
from palisade_sec.judge.base import JudgeError
from palisade_sec.judge.types import (
    ChoiceAns,
    ChoiceQ,
    JudgeResult,
    NoulAns,
    NoulQ,
    Question,
    ScoreAns,
    ScoreQ,
)

DEFAULT_ENDPOINT = "https://api.typesafe.ai"
DEFAULT_MODEL = "jev-latest"


def _question_json(q: Question) -> dict:
    if isinstance(q, NoulQ):
        out: dict = {"type": "noul", "instructions": q.instructions}
        if q.criteria:
            out["criteria"] = q.criteria
        return out
    if isinstance(q, ChoiceQ):
        return {"type": "choice", "instructions": q.instructions, "criteria": q.criteria}
    if isinstance(q, ScoreQ):
        return {"type": "score", "instructions": q.instructions, "criteria": q.levels}
    raise JudgeError(f"unknown question type {type(q).__name__}")


class TypeSafeBackend:
    name = "typesafe"

    def __init__(
        self,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        model: str = DEFAULT_MODEL,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        # "Calibrated" is a property of the real TypeSafe service, not of this
        # adapter. Any other endpoint speaking the same protocol is unverified,
        # so it gets the unverified posture cap and can never BLOCK on its own.
        self.verified = self.endpoint == DEFAULT_ENDPOINT.rstrip("/")
        self._client = client or httpx.Client()

    def ask(self, state: object, questions: list[Question]) -> JudgeResult:
        body = {
            "state": state,
            "model": self.model,
            "questions": {q.id: _question_json(q) for q in questions},
        }
        data = post_json(self._client, f"{self.endpoint}/v1/systemone", self._api_key, body)
        answers = _parse_answers(data.get("answers", {}))
        return JudgeResult(
            answers=answers,
            backend=self.name,
            verified=self.verified,
            usage=data.get("usage", {}) if isinstance(data.get("usage"), dict) else {},
        )


def _parse_answers(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise JudgeError("TypeSafe response missing an `answers` object")
    out: dict = {}
    for qid, a in raw.items():
        if not isinstance(a, dict):
            raise JudgeError(f"malformed answer for {qid!r}")
        kind = a.get("type")
        try:
            if kind == "noul":
                out[qid] = NoulAns(value=float(a["noul"]))
            elif kind == "choice":
                out[qid] = ChoiceAns(
                    choice=str(a["choice"]),
                    probabilities={k: float(v) for k, v in a.get("probabilities", {}).items()},
                    confidence=_opt_float(a.get("confidence")),
                )
            elif kind == "score":
                out[qid] = ScoreAns(
                    score=float(a["score"]),
                    confidence=_opt_float(a.get("confidence")),
                )
            else:
                raise JudgeError(f"unknown answer type {kind!r} for {qid!r}")
        except (KeyError, TypeError, ValueError) as exc:
            raise JudgeError(f"malformed {kind} answer for {qid!r}") from exc
    return out


def _opt_float(v: object) -> float | None:
    return float(v) if isinstance(v, (int, float)) else None
