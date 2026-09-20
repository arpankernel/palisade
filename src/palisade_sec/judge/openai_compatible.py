"""Generic OpenAI-compatible adapter (best-effort, unverified).

Wraps the questions in a strict-JSON instruction, calls a chat-completions
endpoint, and validates the reply against a pydantic schema built from the
questions. Because the answers are not calibrated, `verified=False` and callers
must not BLOCK on judgment from this backend alone.

Works against any endpoint exposing POST {endpoint}/chat/completions with the
OpenAI request/response shape (OpenAI, vLLM, Ollama's OpenAI mode, LiteLLM, ...).
"""

from __future__ import annotations

import json

import httpx
from pydantic import ValidationError, create_model

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

_SYSTEM = (
    "You are a precise evaluation function, not a chatbot. Read the `state` and "
    "answer each question. Respond with ONLY a single JSON object and no prose, "
    "no code fences. Map each question id to its answer: a noul answer is a number "
    "from 0 to 1 (probability the statement is true); a score answer is a number "
    "from 0 to N (the level index); a choice answer is exactly one of the listed "
    "option keys."
)


def _questions_spec(questions: list[Question]) -> list[dict]:
    spec: list[dict] = []
    for q in questions:
        if isinstance(q, NoulQ):
            spec.append(
                {
                    "id": q.id,
                    "type": "noul",
                    "instructions": q.instructions,
                    "answer": "number 0..1",
                }
            )
        elif isinstance(q, ChoiceQ):
            spec.append(
                {
                    "id": q.id,
                    "type": "choice",
                    "instructions": q.instructions,
                    "options": list(q.criteria.keys()),
                }
            )
        elif isinstance(q, ScoreQ):
            spec.append(
                {
                    "id": q.id,
                    "type": "score",
                    "instructions": q.instructions,
                    "levels": {i: d for i, d in enumerate(q.levels)},
                }
            )
    return spec


def _schema_model(questions: list[Question]):
    fields: dict = {}
    for q in questions:
        fields[q.id] = (str, ...) if isinstance(q, ChoiceQ) else (float, ...)
    return create_model("GenericJudgeResponse", **fields)


class OpenAICompatibleBackend:
    name = "openai_compatible"
    verified = False

    def __init__(
        self,
        api_key: str,
        endpoint: str,
        model: str,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self._client = client or httpx.Client()

    def ask(self, state: object, questions: list[Question]) -> JudgeResult:
        user = json.dumps({"state": state, "questions": _questions_spec(questions)})
        body = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": user},
            ],
        }
        data = post_json(self._client, f"{self.endpoint}/chat/completions", self._api_key, body)
        content = _extract_content(data)
        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise JudgeError("model reply was not valid JSON") from exc
        model = _schema_model(questions)
        try:
            validated = model.model_validate(parsed).model_dump()
        except ValidationError as exc:
            raise JudgeError(
                f"model reply failed schema validation ({exc.error_count()} error(s))"
            ) from exc
        answers = _to_answers(questions, validated)
        return JudgeResult(
            answers=answers,
            backend=self.name,
            verified=self.verified,
            usage=data.get("usage", {}) if isinstance(data.get("usage"), dict) else {},
        )


def _extract_content(data: dict) -> str:
    try:
        return str(data["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise JudgeError("completion response had no message content") from exc


def _to_answers(questions: list[Question], validated: dict) -> dict:
    out: dict = {}
    for q in questions:
        raw = validated[q.id]
        if isinstance(q, NoulQ):
            v = float(raw)
            if not 0.0 <= v <= 1.0:
                raise JudgeError(f"noul answer {q.id!r} out of range: {v}")
            out[q.id] = NoulAns(value=v)
        elif isinstance(q, ScoreQ):
            v = float(raw)
            if not 0.0 <= v <= len(q.levels) - 1:
                raise JudgeError(f"score answer {q.id!r} out of range: {v}")
            out[q.id] = ScoreAns(score=v, confidence=None)
        elif isinstance(q, ChoiceQ):
            if raw not in q.criteria:
                raise JudgeError(f"choice answer {q.id!r} not an option: {raw!r}")
            out[q.id] = ChoiceAns(choice=str(raw), probabilities={}, confidence=None)
    return out
