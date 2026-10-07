"""Redaction of anything the judgment layer is about to send.

A snippet is a line of the user's real source, so a snippet can hold a real
credential. These tests cover the three outcomes that matter: a secret is
masked, a safe payload survives intact, and a payload redaction cannot prove
safe is reported rather than passed through.
"""

from __future__ import annotations

import pytest

from palisade_sec.judge.redact import MASK, Redaction, redact_state, redact_text

# Fabricated, pattern-shaped, never real. Each is long enough to trip its own
# detector and nothing here is a live credential.
SECRETS = [
    "sk-ant-api03-" + "A" * 40,
    "sk-" + "B" * 36,
    "ghp_" + "C" * 36,
    "github_pat_" + "D" * 30,
    "glpat-" + "E" * 20,
    "AKIAIOSFODNN7EXAMPLE",
    "xoxb-123456789012-" + "F" * 24,
    "AIza" + "G" * 35,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_a_provider_key_is_masked(secret: str) -> None:
    text, count = redact_text(f"client = Thing(api_key='{secret}')")
    assert count >= 1
    assert secret not in text
    assert MASK in text


def test_a_private_key_block_is_masked_whole() -> None:
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    text, count = redact_text(body)
    assert count >= 1
    assert "MIIEowIBAAKCAQEA" not in text


def test_a_url_password_is_masked_but_the_shape_survives() -> None:
    text, count = redact_text('DSN = "postgresql://admin:hunter2horse@db.internal/app"')
    assert count >= 1
    assert "hunter2horse" not in text
    # The judge still has to be able to tell this was a connection string.
    assert "postgresql://" in text
    assert "db.internal" in text


def test_the_assignment_form_masks_the_value_and_keeps_the_name() -> None:
    text, _ = redact_text('PASSWORD = "correct-horse-battery"')
    assert "correct-horse-battery" not in text
    assert "PASSWORD" in text


def test_ordinary_source_is_not_mangled() -> None:
    """Over-redaction costs the judge its evidence, so the common shapes that
    look secret-adjacent must survive."""
    safe = [
        "cur.execute('SELECT * FROM orders WHERE id = ?', (order_id,))",
        "key = os.environ['API_KEY']",
        "token = request.headers.get('Authorization')",
        "digest = hashlib.sha256(body).hexdigest()",
        "uid = '550e8400-e29b-41d4-a716-446655440000'",
        "exec(llm_response)",
    ]
    for line in safe:
        text, count = redact_text(line)
        assert count == 0, line
        assert text == line


def test_a_nested_state_is_redacted_throughout() -> None:
    state = {
        "rule": "PI-EXEC",
        "source": f"key = '{SECRETS[0]}'",
        "partial_defenses": [{"kind": f"token {SECRETS[2]}"}],
    }
    red = redact_state(state)
    assert red.safe
    assert red.count >= 2
    blob = repr(red.state)
    assert SECRETS[0] not in blob
    assert SECRETS[2] not in blob
    assert "PI-EXEC" in blob


def test_redaction_copies_and_never_mutates_the_caller_state() -> None:
    """The local report still shows the user their own code, so the original
    payload must come back untouched."""
    original = {"source": f"k = '{SECRETS[1]}'"}
    red = redact_state(original)
    assert original["source"].endswith("'"), "caller state was mutated"
    assert SECRETS[1] in original["source"]
    assert SECRETS[1] not in repr(red.state)


def test_a_type_the_walk_cannot_inspect_is_unredactable() -> None:
    """Fail closed. An object this module cannot walk is unknown, and unknown
    is reported rather than sent."""

    class Opaque:
        def __repr__(self) -> str:  # pragma: no cover - must never be called
            raise AssertionError("repr would be the leak")

    red = redact_state({"thing": Opaque()})
    assert not red.safe
    assert any("Opaque" in r for r in red.unredactable)


def test_an_unredactable_reason_names_a_type_and_path_not_a_value() -> None:
    red = redact_state({"creds": object()})
    assert not red.safe
    joined = " ".join(red.unredactable)
    assert "creds" in joined
    assert "object" in joined
    assert MASK not in joined


def test_a_secret_that_survives_the_first_pass_is_unredactable(monkeypatch) -> None:
    """The second pass is the belt to the first pass's braces: if a pattern
    still fires after masking, the masking did not hold."""
    import palisade_sec.judge.redact as mod

    monkeypatch.setattr(mod, "redact_text", lambda text: (text, 0))
    red = mod.redact_state({"source": f"k = '{SECRETS[0]}'"})
    assert not red.safe
    assert any("survived redaction" in r for r in red.unredactable)


def test_a_cycle_is_bounded_rather_than_hanging() -> None:
    node: dict = {"name": "a"}
    node["child"] = node
    red = redact_state(node)
    assert not red.safe
    assert any("deeper than" in r for r in red.unredactable)


def test_scalars_pass_through_unchanged() -> None:
    red = redact_state({"line": 42, "ok": True, "p": 0.5, "none": None})
    assert red.safe
    assert red.state == {"line": 42, "ok": True, "p": 0.5, "none": None}


def test_redaction_dataclass_reports_safe_only_when_clean() -> None:
    assert Redaction(state={}, count=0, unredactable=()).safe
    assert not Redaction(state={}, count=0, unredactable=("x",)).safe
