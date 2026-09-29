"""Slack connection: an incoming webhook, and the Block Kit message builder.

A webhook URL is itself the secret (anyone holding it can post to the
channel), so it is stored like a token and never printed in full.

The scanner does not post anything. `palisade-sec notify --slack` is an
explicit command, and in CI the Action passes the webhook from the caller's
own secret. Nothing is ever sent automatically.
"""

from __future__ import annotations

import json
import re

from palisade_sec.connect.http import HttpError, post_text
from palisade_sec.connect.store import SLACK_WEBHOOK, Resolved, get_credential

WEBHOOK_RE = re.compile(r"^https://hooks\.slack\.com/(services|workflows)/[A-Za-z0-9/_-]+$")

_SEV_EMOJI = {"high": ":red_circle:", "med": ":large_orange_circle:", "low": ":white_circle:"}


class SlackError(RuntimeError):
    """A Slack problem, stated without echoing the webhook URL."""


def resolve_webhook() -> Resolved | None:
    return get_credential(SLACK_WEBHOOK)


def validate_webhook(url: str) -> None:
    if not WEBHOOK_RE.match(url.strip()):
        raise SlackError(
            "that does not look like a Slack incoming webhook. Expected "
            "https://hooks.slack.com/services/... - create one at "
            "https://api.slack.com/messaging/webhooks"
        )


def post(url: str, text: str, blocks: list[dict] | None = None) -> None:
    payload: dict = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    try:
        body = post_text(url, json.dumps(payload))
    except HttpError as exc:
        if exc.status == 404:
            raise SlackError("Slack returned 404: the webhook no longer exists.") from None
        if exc.status == 403:
            raise SlackError("Slack returned 403: the webhook was revoked.") from None
        raise SlackError(f"Slack rejected the message ({exc}).") from None
    if body.lower() != "ok":
        raise SlackError(f"Slack replied {body[:80]!r} instead of ok.")


def build_blocks(
    *,
    project: str,
    high: int,
    med: int,
    findings: list,
    files_scanned: int,
    link: str | None = None,
    new_only: bool = False,
) -> tuple[str, list[dict]]:
    """A Block Kit message for a scan result. Returns (fallback text, blocks).

    Deliberately compact: a channel post is a prompt to go look, not the
    report. At most five findings are listed.
    """
    scope = "new " if new_only else ""
    if not findings:
        text = f"Palisade: no {scope}findings in {project} ({files_scanned} files)"
        return text, [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f":white_check_mark: *{text}*"},
            }
        ]

    text = f"Palisade: {high} high, {med} med {scope}finding(s) in {project}"
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": "Prompt injection found"}},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{project}* - {high} high, {med} med {scope}finding(s) "
                    f"across {files_scanned} file(s)"
                ),
            },
        },
    ]
    for f in findings[:5]:
        emoji = _SEV_EMOJI.get(f.severity, ":white_circle:")
        maps = ", ".join(f.owasp_llm) if f.owasp_llm else ""
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{f.rule_id}* `{f.file}:{f.line}`\n"
                        f"`{_clip(f.sink.snippet)}`\n"
                        f"_{_clip(f.attack.strip(), 160)}_" + (f"\n{maps}" if maps else "")
                    ),
                },
            }
        )
    if len(findings) > 5:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"and {len(findings) - 5} more"},
                ],
            }
        )
    if link:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in GitHub"},
                        "url": link,
                    }
                ],
            }
        )
    return text, blocks


def _clip(s: str, n: int = 120) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"
