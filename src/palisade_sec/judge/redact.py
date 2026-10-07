"""Secret redaction for anything the judgment layer is about to send.

The offline core never reaches this module. It exists for one reason: a
finding's snippets are lines of the user's real source, and a line of real
source can hold a real credential. `audit` and `review` send those snippets to
an endpoint, so a secret in a snippet is a secret transmitted.

Two rules shape the design.

1. Redact before the state leaves, not after. The caller gets back a copy; the
   original finding is untouched, so the local report still shows the user
   their own code.
2. When redaction cannot prove a value is safe, say so and let the caller fail
   closed. A value of a type this module cannot walk is not "probably fine":
   it is unknown, and unknown is reported, never sent.

The patterns are deliberately high-confidence. Over-redaction costs the judge
a little context; under-redaction leaks a credential, so the asymmetry is
resolved in favour of masking. Entropy heuristics are not used: they fire on
hashes, UUIDs and minified code, which would hollow out the evidence without
catching anything the explicit patterns miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MASK = "[redacted]"

# How deep the walk goes before it gives up and reports the state as
# unwalkable. Real state is three or four levels; anything deeper is either a
# cycle or a structure this layer was not designed to send.
MAX_DEPTH = 12

# A path component is printed only when it is a plain identifier. A dict key
# can itself be a credential, so anything else becomes a placeholder.
_SAFE_PATH_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,40}$")

# (pattern, group to mask). Group 0 masks the whole match.
_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    # Private keys. The header alone is enough: the body follows it.
    (re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----.*?-----END[ A-Z]*PRIVATE KEY-----", re.S), 0),
    (re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----"), 0),
    # Provider-issued keys, each with a vendor prefix that makes a false
    # positive very unlikely.
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), 0),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), 0),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), 0),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), 0),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{18,}"), 0),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), 0),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0),
    # A JWT carries its own claims and is a bearer token in practice.
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 0),
    # Webhook URLs, where the whole URL is the credential. These have no vendor
    # token prefix and often sit in source under a name the assignment pattern
    # below does not recognise ("SLACK", "ALERTS", "NOTIFY"), so they need a
    # rule of their own. Found by checking the patterns against a real webhook
    # shape rather than against the list that built them.
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_\-]+)+"), 0),
    (
        re.compile(
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{20,}"
        ),
        0,
    ),
    (
        re.compile(r"https://[A-Za-z0-9.\-]*\.webhook\.office\.com/webhookb2/[A-Za-z0-9@/\-]{20,}"),
        0,
    ),
    # Credentials inside a URL: mask the password, keep the shape so the judge
    # can still tell a connection string from a plain path.
    (re.compile(r"(?P<pre>[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:)(?P<secret>[^\s/@]+)(?=@)"), 2),
    # The assignment form, which is how a credential usually appears in source.
    # Masks the quoted value only, so the name stays readable as evidence.
    (
        re.compile(
            r"""(?ix)
            \b(?:api[_\-]?key|apikey|secret|secret[_\-]?key|password|passwd|pwd
               |token|auth[_\-]?token|access[_\-]?key|private[_\-]?key
               |client[_\-]?secret|connection[_\-]?string|webhook|webhook[_\-]?url
               |dsn|credential|credentials)\b
            \s*[:=]\s*
            (?P<q>['"])(?P<secret>[^'"]{8,})(?P=q)
            """
        ),
        2,
    ),
)


@dataclass(frozen=True)
class Redaction:
    """The outcome of redacting one state payload.

    `unredactable` is the only field a caller must branch on. When it is
    non-empty the state must NOT be sent, whatever `count` says. Each entry
    names a type and a path, never a value, so the reason itself can be
    printed and logged.
    """

    state: object
    count: int
    unredactable: tuple[str, ...]

    @property
    def safe(self) -> bool:
        return not self.unredactable


def redact_text(text: str) -> tuple[str, int]:
    """Mask every secret in one string. Returns the text and how many were
    masked."""
    count = 0
    out = text
    for pattern, group in _PATTERNS:

        def _sub(m: re.Match[str], g: int = group) -> str:
            nonlocal count
            count += 1
            if g == 0:
                return MASK
            # Keep everything around the secret, mask the secret itself.
            start, end = m.span(g)
            return m.group(0)[: start - m.start()] + MASK + m.group(0)[end - m.start() :]

        out = pattern.sub(_sub, out)
    return out, count


def safe_reason(text: str, limit: int = 300) -> str:
    """Make text from outside safe to put in an exception, a log or a report.

    Used on anything an endpoint or a model hands back. A provider's error
    message is the actionable part of a failure, so it is worth showing, but
    it is still text this process did not write: a hostile endpoint can echo
    the Authorization header, and a legitimate one can echo the request body,
    which carries the scanned code. Redacting first makes `JudgeError`'s
    promise that it carries neither the key nor the prompt true rather than
    assumed.
    """
    cleaned, _ = redact_text(text)
    return cleaned[:limit]


def _detects(text: str) -> bool:
    return any(pattern.search(text) for pattern, _ in _PATTERNS)


def _path(parts: tuple[str, ...]) -> str:
    return ".".join(parts) if parts else "<root>"


def redact_state(state: object) -> Redaction:
    """Walk a state payload and mask every secret in it.

    Containers are rebuilt rather than mutated, so the caller's finding is
    never altered. Anything this function cannot walk is reported in
    `unredactable` instead of being passed through.
    """
    total = 0
    problems: list[str] = []

    def walk(value: object, parts: tuple[str, ...], depth: int) -> object:
        nonlocal total
        if depth > MAX_DEPTH:
            problems.append(f"nested deeper than {MAX_DEPTH} levels at {_path(parts)}")
            return MASK
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            cleaned, n = redact_text(value)
            total += n
            # Second pass. If a pattern still fires on the cleaned text, the
            # masking did not hold (overlapping matches, a pathological
            # input), and the only safe answer is to refuse to send it.
            if _detects(cleaned):
                problems.append(f"a secret survived redaction at {_path(parts)}")
                return MASK
            return cleaned
        if isinstance(value, (list, tuple)):
            return [walk(v, (*parts, str(i)), depth + 1) for i, v in enumerate(value)]
        if isinstance(value, dict):
            out: dict[str, object] = {}
            for key, v in value.items():
                if not isinstance(key, str):
                    problems.append(f"dict key of type {type(key).__name__} at {_path(parts)}")
                    continue
                safe_key, n = redact_text(key)
                total += n
                label = key if _SAFE_PATH_KEY.match(key) else "<key>"
                out[safe_key] = walk(v, (*parts, label), depth + 1)
            return out
        problems.append(f"value of type {type(value).__name__} at {_path(parts)}")
        return MASK

    cleaned = walk(state, (), 0)
    return Redaction(state=cleaned, count=total, unredactable=tuple(problems))
