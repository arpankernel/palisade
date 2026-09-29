"""Minimal JSON-over-HTTPS helper for the connected commands.

stdlib only, on purpose: the base install stays dependency-free for
networking, and `scan`/`map`/`baseline`/`fix` never import this module. Every
request is https, has a timeout, and carries a version-stamped user agent.
Errors never include the Authorization header or the request body.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from palisade_sec import __version__

USER_AGENT = f"palisade-sec/{__version__}"
TIMEOUT = 30.0


class HttpError(RuntimeError):
    """A failed request. Carries the status and a short body excerpt only."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = TIMEOUT,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Send a JSON request and parse a JSON response. Returns (data, headers)."""
    if not url.startswith("https://"):
        raise HttpError(0, f"refusing a non-https URL: {url.split('://', 1)[0]}://…")
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=payload, method=method)  # noqa: S310 - https enforced
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
            got = dict(resp.headers.items())
            status = resp.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200].strip()
        raise HttpError(exc.code, f"HTTP {exc.code}: {detail or exc.reason}") from None
    except urllib.error.URLError as exc:
        raise HttpError(0, f"could not reach {_host(url)}: {exc.reason}") from None
    except TimeoutError:
        raise HttpError(0, f"timed out after {timeout:.0f}s talking to {_host(url)}") from None
    if not raw.strip():
        return {}, got
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise HttpError(status, f"{_host(url)} returned a non-JSON response") from None
    return (data if isinstance(data, dict) else {"data": data}), got


def post_form(url: str, fields: dict[str, str], *, timeout: float = TIMEOUT) -> dict[str, Any]:
    """Form-encoded POST that asks for a JSON reply (GitHub's OAuth endpoints)."""
    import urllib.parse

    if not url.startswith("https://"):
        raise HttpError(0, "refusing a non-https URL")
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")  # noqa: S310 - https enforced
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code, f"HTTP {exc.code} from {_host(url)}") from None
    except urllib.error.URLError as exc:
        raise HttpError(0, f"could not reach {_host(url)}: {exc.reason}") from None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise HttpError(0, f"{_host(url)} returned a non-JSON response") from None
    return parsed if isinstance(parsed, dict) else {}


def post_text(url: str, body: str, *, timeout: float = TIMEOUT) -> str:
    """POST a raw body (Slack webhooks answer with `ok`, not JSON)."""
    if not url.startswith("https://"):
        raise HttpError(0, "refusing a non-https URL")
    req = urllib.request.Request(  # noqa: S310 - https enforced
        url, data=body.encode(), method="POST"
    )
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            text: str = resp.read().decode("utf-8", errors="replace")
            return text.strip()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200].strip()
        raise HttpError(exc.code, f"HTTP {exc.code}: {detail or exc.reason}") from None
    except urllib.error.URLError as exc:
        raise HttpError(0, f"could not reach {_host(url)}: {exc.reason}") from None


def _host(url: str) -> str:
    """Host only: a full URL can carry a webhook secret in its path."""
    import urllib.parse

    return urllib.parse.urlsplit(url).netloc or "the endpoint"
