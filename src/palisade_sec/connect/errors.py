"""The common base for every connected-surface failure.

Connecting GitHub, Slack or an LLM fails in ordinary ways all the time: a
mistyped webhook, an expired token, a key without the right scope. Those
are the user's situation to fix, not bugs in Palisade, so they must exit 2
with the sentence that says what to do - never through the last-resort
handler in `cli.run`, which exits 3 and asks for a bug report.

Every exception raised on purpose in this package inherits from
`ConnectError`, and `tests/test_connect_errors.py` fails if a new one does
not, so the next surface cannot quietly reintroduce the mislabelling.
"""

from __future__ import annotations


class ConnectError(RuntimeError):
    """A connected-surface problem, phrased as what to do next.

    Never carries a credential: the message is what the user reads.
    """
