"""Judge adapters + config, exercised offline with httpx MockTransport. No
network, no real endpoint, no key required. Keys must never appear in errors."""

from __future__ import annotations

import json

import httpx
import pytest

from palisade_sec.judge import config as jconfig
from palisade_sec.judge.base import JudgeError
from palisade_sec.judge.openai_compatible import OpenAICompatibleBackend
from palisade_sec.judge.types import NoulQ, ScoreQ
from palisade_sec.judge.typesafe import TypeSafeBackend

QUESTIONS = [
    NoulQ(id="irreversible", instructions="Can it take an irreversible action?"),
    ScoreQ(id="harm", instructions="How much harm?", levels=["none", "some", "much", "severe"]),
]


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# -- TypeSafe adapter -------------------------------------------------------


def test_typesafe_maps_questions_and_parses_answers():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "jev-latest",
                "answers": {
                    "irreversible": {"type": "noul", "noul": 0.91},
                    "harm": {"type": "score", "score": 2.4, "confidence": 0.8},
                },
                "usage": {"input_tokens": 10, "output_tokens": 3},
            },
        )

    # The default endpoint (the real service) is the only verified one; the
    # mocked client intercepts the request, so nothing leaves the process.
    b = TypeSafeBackend(api_key="k-secret", client=_client(handler))
    result = b.ask({"tool_name": "wipe"}, QUESTIONS)

    assert seen["url"].endswith("/v1/systemone")
    assert seen["auth"] == "Bearer k-secret"
    assert seen["body"]["questions"]["irreversible"]["type"] == "noul"
    assert seen["body"]["questions"]["harm"]["type"] == "score"
    assert result.verified is True
    assert result.noul("irreversible") == pytest.approx(0.91)
    assert result.score("harm") == pytest.approx(2.4)
    assert result.usage["output_tokens"] == 3


def test_typesafe_raises_on_http_error():
    b = TypeSafeBackend(
        api_key="k", endpoint="https://ts.test", client=_client(lambda r: httpx.Response(500))
    )
    with pytest.raises(JudgeError):
        b.ask("state", QUESTIONS)


def test_typesafe_raises_on_malformed_answer():
    def handler(r):
        return httpx.Response(200, json={"answers": {"irreversible": {"type": "noul"}}})

    b = TypeSafeBackend(api_key="k", endpoint="https://ts.test", client=_client(handler))
    with pytest.raises(JudgeError):
        b.ask("state", [NoulQ(id="irreversible", instructions="?")])


# -- OpenAI-compatible adapter ---------------------------------------------


def _completion(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def test_openai_compatible_validates_and_maps():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return _completion(json.dumps({"irreversible": 0.8, "harm": 2}))

    b = OpenAICompatibleBackend(
        api_key="k", endpoint="https://oai.test/v1", model="gpt-x", client=_client(handler)
    )
    result = b.ask({"tool_name": "wipe"}, QUESTIONS)

    assert seen["url"].endswith("/chat/completions")
    assert result.verified is False
    assert result.backend == "openai_compatible"
    assert result.noul("irreversible") == pytest.approx(0.8)
    assert result.score("harm") == pytest.approx(2.0)


def test_openai_compatible_rejects_out_of_range():
    b = OpenAICompatibleBackend(
        api_key="k",
        endpoint="https://oai.test",
        model="m",
        client=_client(lambda r: _completion('{"irreversible": 1.7, "harm": 1}')),
    )
    with pytest.raises(JudgeError):
        b.ask("s", QUESTIONS)


def test_openai_compatible_rejects_non_json_content():
    b = OpenAICompatibleBackend(
        api_key="k",
        endpoint="https://oai.test",
        model="m",
        client=_client(lambda r: _completion("not json at all")),
    )
    with pytest.raises(JudgeError):
        b.ask("s", QUESTIONS)


def test_openai_compatible_rejects_missing_field():
    b = OpenAICompatibleBackend(
        api_key="k",
        endpoint="https://oai.test",
        model="m",
        client=_client(lambda r: _completion('{"irreversible": 0.5}')),
    )
    with pytest.raises(JudgeError):
        b.ask("s", QUESTIONS)


# -- config -----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_dotenv(monkeypatch):
    # Never read a real .env during config tests.
    monkeypatch.setattr(jconfig, "_dotenv_values", lambda: {})
    for var in (
        jconfig.BACKEND_ENV,
        jconfig.ENDPOINT_ENV,
        jconfig.MODEL_ENV,
        jconfig.TYPESAFE_KEY_ENV,
        jconfig.GENERIC_KEY_ENV,
    ):
        monkeypatch.delenv(var, raising=False)


def test_config_defaults_to_typesafe(monkeypatch):
    monkeypatch.setenv(jconfig.TYPESAFE_KEY_ENV, "k")
    backend = jconfig.get_backend()
    assert backend.name == "typesafe"
    assert backend.verified is True


def test_config_missing_typesafe_key_names_the_var():
    with pytest.raises(JudgeError) as exc:
        jconfig.get_backend()
    assert jconfig.TYPESAFE_KEY_ENV in str(exc.value)


def test_config_openai_compatible_requires_endpoint_and_model(monkeypatch):
    monkeypatch.setenv(jconfig.BACKEND_ENV, "openai_compatible")
    monkeypatch.setenv(jconfig.GENERIC_KEY_ENV, "super-secret-value")
    # endpoint missing
    with pytest.raises(JudgeError) as exc:
        jconfig.get_backend()
    msg = str(exc.value)
    assert jconfig.ENDPOINT_ENV in msg
    assert "super-secret-value" not in msg  # key value never leaks into errors


def test_config_openai_compatible_ok(monkeypatch):
    monkeypatch.setenv(jconfig.BACKEND_ENV, "openai_compatible")
    monkeypatch.setenv(jconfig.GENERIC_KEY_ENV, "k")
    monkeypatch.setenv(jconfig.ENDPOINT_ENV, "https://oai.test/v1")
    monkeypatch.setenv(jconfig.MODEL_ENV, "gpt-x")
    backend = jconfig.get_backend()
    assert backend.name == "openai_compatible"
    assert backend.verified is False


def test_config_rejects_unknown_backend(monkeypatch):
    monkeypatch.setenv(jconfig.BACKEND_ENV, "nonsense")
    with pytest.raises(JudgeError):
        jconfig.get_backend()


def test_typesafe_protocol_on_another_endpoint_is_unverified():
    """Pointing PALISADE_JUDGE_ENDPOINT anywhere else must not inherit the
    real service's "calibrated" label, or it would bypass the posture cap for
    unverified backends."""
    b = TypeSafeBackend(api_key="k", endpoint="http://127.0.0.1:9", client=_client(lambda r: None))
    assert b.verified is False
