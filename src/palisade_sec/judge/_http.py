"""Shared HTTP for the judgment adapters.

One place to POST JSON and fail safely. Error messages never include request
headers (which carry the key) or the response body (which echoes the prompt).
Responses are size-capped so a hostile endpoint cannot exhaust memory.
"""

from __future__ import annotations

import httpx

from palisade_sec.judge.base import JudgeError

MAX_RESPONSE_BYTES = 5_000_000
DEFAULT_TIMEOUT = 30.0


def post_json(
    client: httpx.Client,
    url: str,
    api_key: str,
    body: dict,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        resp = client.post(url, headers=headers, json=body, timeout=timeout)
    except httpx.HTTPError as exc:
        # str(exc) may include the URL but never the key or body.
        raise JudgeError(f"judge request failed: {type(exc).__name__}") from exc
    if resp.status_code >= 400:
        raise JudgeError(f"judge endpoint returned HTTP {resp.status_code}")
    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise JudgeError("judge response exceeded size cap")
    try:
        data = resp.json()
    except ValueError as exc:
        raise JudgeError("judge response was not valid JSON") from exc
    if not isinstance(data, dict):
        raise JudgeError("judge response was not a JSON object")
    return data
