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
from palisade_sec.judge.guard import SYSTEM_BOUNDARY
from palisade_sec.judge.openai_compatible import _questions_spec, _schema_model, _to_answers
from palisade_sec.judge.redact import safe_reason
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
    "option keys. " + SYSTEM_BOUNDARY
)


def _why(resp: httpx.Response) -> str:
    """The provider's reason for a failure, and nothing else.

    Anthropic answers an error as {"error": {"message": ...}}. That message is
    the actionable part, so the message is taken alone and the surrounding
    body, which can echo the request, is dropped.

    The message itself is still text this process did not write. The endpoint
    can be redirected by config, and even an honest provider may quote the
    request back. So it goes through redaction before it reaches the
    exception: `JudgeError` promises it carries neither the key nor the
    prompt, and this is where that promise is kept rather than assumed.
    """
    try:
        payload = resp.json()
    except ValueError:
        return "no reason given"
    reason = (payload or {}).get("error", {}).get("message") if isinstance(payload, dict) else None
    return safe_reason(str(reason)) if reason else "no reason given"


class AnthropicBackend:
    name = "anthropic"
    verified = False

    def __init__(
        self,
        api_key: str,
        endpoint: str = DEFAULT_ENDPOINT,
        model: str = DEFAULT_MODEL,
        client: httpx.Client | None = None,
        workspace_id: str = "",
    ) -> None:
        self._api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        # Organization keys are not scoped to a workspace and are rejected
        # without this. Sent here as well as on the connect probe, so a key
        # that verifies is a key that works.
        self._workspace_id = workspace_id
        self._client = client or httpx.Client()

    def _headers(self) -> dict[str, str]:
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        if self._workspace_id:
            headers["anthropic-workspace-id"] = self._workspace_id
        return headers

    def ask(self, state: object, questions: list[Question]) -> JudgeResult:
        user = json.dumps({"state": state, "questions": _questions_spec(questions)})
        # No `temperature`. Current Claude models reject it outright - "`
        # temperature` is deprecated for this model", HTTP 400 - which broke
        # `audit` entirely against the default backend while `connect llm`
        # still reported the key as verified, because the probe does not send
        # it. A key that verifies has to be a key that works.
        #
        # It was there for reproducible judgments. That property now rests on
        # the schema-validated reply and on temperature 0 being the API's own
        # default for these models, which is weaker - and is one more reason
        # the judged layer is labelled advisory rather than calibrated.
        body = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
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
                headers=self._headers(),
                timeout=60.0,
            )
        except httpx.HTTPError as exc:
            raise JudgeError(f"could not reach the Anthropic API: {type(exc).__name__}") from None
        if resp.status_code == 401:
            raise JudgeError("Anthropic rejected the API key (401).")
        if resp.status_code == 429:
            raise JudgeError("Anthropic rate limit (429); retry later.")
        if resp.status_code >= 400:
            # Carry the provider's own explanation. Withholding it is what
            # turned a one-line configuration bug into `HTTP 400.` with nothing
            # to search for. Only `error.message` is taken, never the raw body:
            # the request echo could contain the code snippets, and the reason
            # field cannot contain the key.
            raise JudgeError(f"Anthropic returned HTTP {resp.status_code}: {_why(resp)}")
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
