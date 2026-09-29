"""Anthropic (Claude) adapter for the judgment layer.

Claude's Messages API is not OpenAI-shaped, so it gets its own adapter
rather than being forced through the generic one. The question spec, the
strict-JSON contract and the schema validation are shared with
`openai_compatible`, so a reply that does not match the schema is an error
here too, never a guess.

Like every bring-your-own-endpoint backend, answers are `verified=False`:
they are advisory and can never BLOCK on judgment alone. Only the
calibrated TypeSafe service is treated as verified.
"""

from __future__ import annotations

import json

import httpx
from pydantic import ValidationError

from palisade_sec.judge.base import JudgeError
from palisade_sec.judge.openai_compatible import _questions_spec, _schema_model, _to_answers
from palisade_sec.judge.types import JudgeResult, Question

DEFAULT_ENDPOINT = "https://api.anthropic.com"
DEFAULT_MODEL = "claude-sonnet-5"
API_VERSION = "2023-06-01"
MAX_TOKENS = 1024

_SYSTEM = (
    "You are a precise evaluation function, not a chatbot. Read the `state` and "
    "answer each question. Respond with ONLY a single JSON object and no prose, "
    "no code fences. Map each question id to its answer: a noul answer is a number "
    "from 0 to 1 (probability the statement is true); a score answer is a number "
    "from 0 to N (the level index); a choice answer is exactly one of the listed "
    "option keys."
)


class AnthropicBackend:
    name = "anthropic"
    verified = False

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
        self._client = client or httpx.Client()

    def ask(self, state: object, questions: list[Question]) -> JudgeResult:
        user = json.dumps({"state": state, "questions": _questions_spec(questions)})
        body = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "temperature": 0,
            "system": _SYSTEM,
            "messages": [{"role": "user", "content": user}],
        }
        data = self._post(f"{self.endpoint}/v1/messages", body)
        content = _extract_text(data)
        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise JudgeError("model reply was not valid JSON") from exc
        try:
            validated = _schema_model(questions).model_validate(parsed).model_dump()
        except ValidationError as exc:
            raise JudgeError(
                f"model reply failed schema validation ({exc.error_count()} error(s))"
            ) from exc
        return JudgeResult(
            answers=_to_answers(questions, validated),
            backend=self.name,
            verified=self.verified,
            usage=data.get("usage", {}) if isinstance(data.get("usage"), dict) else {},
        )

    def _post(self, url: str, body: dict) -> dict:
        """Anthropic uses `x-api-key`, not a bearer token. Errors never carry
        the key or the request body."""
        try:
            resp = self._client.post(
                url,
                json=body,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": API_VERSION,
                    "content-type": "application/json",
                },
                timeout=60.0,
            )
        except httpx.HTTPError as exc:
            raise JudgeError(f"could not reach the Anthropic API: {type(exc).__name__}") from None
        if resp.status_code == 401:
            raise JudgeError("Anthropic rejected the API key (401).")
        if resp.status_code == 429:
            raise JudgeError("Anthropic rate limit (429); retry later.")
        if resp.status_code >= 400:
            raise JudgeError(f"Anthropic returned HTTP {resp.status_code}.")
        try:
            data = resp.json()
        except ValueError:
            raise JudgeError("Anthropic returned a non-JSON response") from None
        return data if isinstance(data, dict) else {}


def _extract_text(data: dict) -> str:
    """Concatenate the text blocks of a Messages API reply."""
    blocks = data.get("content")
    if not isinstance(blocks, list):
        raise JudgeError("Anthropic response had no content blocks")
    text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and "text" in b)
    if not text.strip():
        raise JudgeError("Anthropic response had no text content")
    return text
