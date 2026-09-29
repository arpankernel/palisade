"""The connected surfaces: credential storage, GitHub, Slack, LLM wiring.

Two properties matter more than the features themselves and are pinned here:

1. The offline core never imports any of this, so `scan` keeps its "no
   network, no key" guarantee.
2. A secret is never printed, and never written anywhere another user can
   read it.

Nothing here touches the real network: every HTTP call is stubbed.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from palisade_sec.cli import app
from palisade_sec.connect import github as gh
from palisade_sec.connect import slack as sl
from palisade_sec.connect import store
from palisade_sec.connect.http import HttpError

runner = CliRunner()

TOKEN = "ghp_exampletokenvalue1234567890"


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    """A private config dir and no keychain, so tests never touch the real one."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("PALISADE_NO_KEYRING", "1")
    for name in (
        "PALISADE_GITHUB_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "PALISADE_SLACK_WEBHOOK",
        "TYPESAFE_API_KEY",
        "ANTHROPIC_API_KEY",
        "PALISADE_JUDGE_API_KEY",
        "PALISADE_JUDGE_BACKEND",
        "PALISADE_JUDGE_ENDPOINT",
        "PALISADE_JUDGE_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(gh, "gh_cli_token", lambda: None)
    return tmp_path


# ---------------------------------------------------------------------------
# The guarantee: the offline core stays offline and keyless
# ---------------------------------------------------------------------------


def test_offline_core_does_not_import_the_connected_code():
    """`scan` must not pull in credential storage or HTTP. A fresh process
    imports the scanner and asserts no connect module was loaded."""
    code = textwrap.dedent(
        """
        import sys
        from palisade_sec.scanner import run_scan  # noqa: F401
        leaked = sorted(m for m in sys.modules if m.startswith("palisade_sec.connect"))
        assert not leaked, leaked
        assert "urllib.request" not in sys.modules, "offline core pulled in urllib.request"
        print("clean")
        """
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout


def test_scan_ignores_stored_credentials(isolated_store, tmp_path):
    """A credential on disk must not change what a scan does."""
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    (tmp_path / "app.py").write_text("x = 1\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    doc = json.loads(result.stdout)
    assert doc["summary"]["files_scanned"] == 1
    assert TOKEN not in result.output


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_file_fallback_roundtrip_and_permissions(isolated_store):
    where = store.set_credential(store.GITHUB_TOKEN, TOKEN)
    path = store.credentials_file()
    assert where == str(path)
    assert store.get_credential(store.GITHUB_TOKEN).value == TOKEN
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert store.delete_credential(store.GITHUB_TOKEN) is True
    assert store.get_credential(store.GITHUB_TOKEN) is None


def test_a_world_readable_credentials_file_is_refused(isolated_store):
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    path = store.credentials_file()
    os.chmod(path, 0o644)
    with pytest.raises(store.CredentialError) as exc:
        store.get_credential(store.GITHUB_TOKEN)
    assert "readable by other users" in str(exc.value)
    assert TOKEN not in str(exc.value)


def test_environment_wins_over_stored_value(isolated_store, monkeypatch):
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    found = store.get_credential(store.GITHUB_TOKEN)
    assert (found.value, found.source) == ("from-env", "env:GITHUB_TOKEN")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("ghp_exampletokenvalue1234", "ghp_…1234"), ("short", "…"), ("", "-")],
)
def test_redaction(value, expected):
    assert store.redact(value) == expected


def test_stored_secret_never_appears_in_output(isolated_store):
    store.set_credential(store.SLACK_WEBHOOK, "https://hooks.slack.com/services/T/B/xoxbSECRET")
    result = runner.invoke(app, ["connections"])
    assert result.exit_code == 0
    assert "xoxbSECRET" not in result.output
    assert "connected" in result.output


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


def test_github_prefers_stored_then_gh_cli(isolated_store, monkeypatch):
    monkeypatch.setattr(gh, "gh_cli_token", lambda: "from-gh")
    assert gh.resolve_token().source == "gh"
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    resolved = gh.resolve_token()
    assert (resolved.value, resolved.source) == (TOKEN, "file")


def test_connect_github_verifies_and_stores(isolated_store, monkeypatch):
    seen = {}

    def fake_request(url, **kw):
        seen["url"] = url
        seen["auth"] = kw["headers"]["Authorization"]
        return {"login": "arpankernel"}, {"X-OAuth-Scopes": "repo, read:org"}

    monkeypatch.setattr(gh, "request_json", fake_request)
    result = runner.invoke(app, ["connect", "github", "--token", TOKEN, "--no-gh"])
    assert result.exit_code == 0, result.output
    assert "arpankernel" in result.output
    assert TOKEN not in result.output
    assert seen["url"].endswith("/user")
    assert store.get_credential(store.GITHUB_TOKEN).value == TOKEN


def test_connect_github_rejects_a_token_without_repo_scope(isolated_store, monkeypatch):
    monkeypatch.setattr(
        gh, "request_json", lambda url, **kw: ({"login": "x"}, {"X-OAuth-Scopes": "gist"})
    )
    result = runner.invoke(app, ["connect", "github", "--token", TOKEN, "--no-gh"])
    assert result.exit_code != 0
    # rich wraps the error into a box: drop the borders before comparing
    flat = " ".join(result.output.replace("\u2502", " ").split())
    assert "needs `repo`" in flat, flat
    assert store.get_credential(store.GITHUB_TOKEN) is None, "a rejected token must not be stored"


def test_github_401_is_a_clean_message(monkeypatch):
    def boom(url, **kw):
        raise HttpError(401, "HTTP 401: Bad credentials")

    monkeypatch.setattr(gh, "request_json", boom)
    with pytest.raises(gh.GitHubError) as exc:
        gh.verify("bad-token")
    assert "401" in str(exc.value)
    assert "bad-token" not in str(exc.value)


def test_device_flow_without_a_client_id_explains_itself(monkeypatch):
    monkeypatch.setattr(gh, "CLIENT_ID", "")
    with pytest.raises(gh.GitHubError) as exc:
        gh.start_device_flow()
    assert "gh auth login" in str(exc.value)


def test_device_flow_polls_until_approved(monkeypatch):
    replies = iter(
        [
            {"error": "authorization_pending"},
            {"error": "slow_down", "interval": 1},
            {"access_token": "gho_granted"},
        ]
    )
    monkeypatch.setattr(gh, "post_form", lambda url, fields: next(replies))
    code = gh.DeviceCode("ABCD-1234", "https://github.com/login/device", "dev", 0, 60)
    assert gh.poll_device_flow(code, client_id="cid", sleep=lambda _s: None) == "gho_granted"


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.slack.com/services/T/B/C",  # not https
        "https://evil.example/services/T/B/C",
        "not a url",
    ],
)
def test_bad_webhooks_are_rejected(url):
    with pytest.raises(sl.SlackError):
        sl.validate_webhook(url)


def test_connect_slack_posts_a_test_message_then_stores(isolated_store, monkeypatch):
    posted = {}

    def fake_post(url, body, timeout=30.0):
        posted["url"], posted["body"] = url, body
        return "ok"

    monkeypatch.setattr("palisade_sec.connect.slack.post_text", fake_post)
    hook = "https://hooks.slack.com/services/T000/B000/xxxxSECRETxxxx"
    result = runner.invoke(app, ["connect", "slack", "--webhook", hook])
    assert result.exit_code == 0, result.output
    assert "xxxxSECRETxxxx" not in result.output
    assert json.loads(posted["body"])["text"].startswith("Palisade is connected")
    assert store.get_credential(store.SLACK_WEBHOOK).value == hook


def test_notify_dry_run_builds_blocks_and_sends_nothing(isolated_store, tmp_path, monkeypatch):
    def explode(*a, **k):
        raise AssertionError("--dry-run must not post")

    monkeypatch.setattr("palisade_sec.connect.slack.post_text", explode)
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "import os\n"
        "def h():\n"
        "    q = request.json['q']\n"
        "    r = client.chat.completions.create(messages=[{'role':'user','content':q}])\n"
        "    os.system(r.choices[0].message.content)\n"
    )
    result = runner.invoke(app, ["notify", str(tmp_path), "--slack", "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert "1 high" in payload["text"]
    assert any("PI-SHELL" in json.dumps(b) for b in payload["blocks"])


def test_notify_without_a_connection_is_a_clean_error(isolated_store, tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    result = runner.invoke(app, ["notify", str(tmp_path), "--slack"])
    assert result.exit_code == 2
    assert "connect slack" in result.output


def test_notify_requires_a_channel(isolated_store, tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    result = runner.invoke(app, ["notify", str(tmp_path)])
    assert result.exit_code == 2
    assert "--slack" in result.output


# ---------------------------------------------------------------------------
# LLM keys reach the judgment layer
# ---------------------------------------------------------------------------


def test_stored_llm_key_configures_the_judge(isolated_store, monkeypatch):
    from palisade_sec.judge import config as jconfig

    monkeypatch.setattr(jconfig, "_dotenv_values", lambda: {})
    store.set_credential(store.LLM_PROVIDER, "anthropic")
    store.set_credential(store.LLM_KEY, "sk-ant-test")
    backend = jconfig.get_backend()
    assert backend.name == "anthropic"
    assert backend.verified is False, "a bring-your-own key is never 'calibrated'"


def test_environment_still_wins_over_a_stored_llm_key(isolated_store, monkeypatch):
    from palisade_sec.judge import config as jconfig

    monkeypatch.setattr(jconfig, "_dotenv_values", lambda: {})
    store.set_credential(store.LLM_PROVIDER, "anthropic")
    store.set_credential(store.LLM_KEY, "sk-ant-stored")
    monkeypatch.setenv("PALISADE_JUDGE_BACKEND", "typesafe")
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts-env")
    assert jconfig.get_backend().name == "typesafe"


def test_disconnect_removes_every_llm_key(isolated_store):
    for key, value in (
        (store.LLM_PROVIDER, "anthropic"),
        (store.LLM_KEY, "sk-ant-test"),
        (store.LLM_MODEL, "claude-sonnet-5"),
    ):
        store.set_credential(key, value)
    result = runner.invoke(app, ["disconnect", "llm"])
    assert result.exit_code == 0
    assert store.get_credential(store.LLM_KEY) is None
    assert store.get_credential(store.LLM_PROVIDER) is None


def test_disconnect_rejects_an_unknown_surface(isolated_store):
    assert runner.invoke(app, ["disconnect", "nope"]).exit_code != 0


def test_credentials_file_is_never_inside_the_scanned_project(isolated_store, tmp_path):
    """Storage lives in the user's config dir, never in a repo where it could
    be committed by accident."""
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    assert Path(os.environ["XDG_CONFIG_HOME"]) in store.credentials_file().parents


class _FakeKeyring:
    """Stand-in for the OS keychain: exercises that branch without touching
    the developer's real keychain."""

    def __init__(self):
        self.data: dict[tuple[str, str], str] = {}

    def get_keyring(self):
        return self

    def get_password(self, service, key):
        return self.data.get((service, key))

    def set_password(self, service, key, value):
        self.data[(service, key)] = value

    def delete_password(self, service, key):
        del self.data[(service, key)]


@pytest.fixture
def fake_keyring(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("PALISADE_NO_KEYRING", raising=False)
    for name in ("PALISADE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    fake = _FakeKeyring()
    monkeypatch.setattr(store, "_keyring", lambda: fake)
    return fake


def test_keychain_is_preferred_and_no_file_is_written(fake_keyring):
    where = store.set_credential(store.GITHUB_TOKEN, TOKEN)
    assert where == "keychain"
    assert fake_keyring.data[(store.SERVICE, store.GITHUB_TOKEN)] == TOKEN
    assert not store.credentials_file().exists(), "the keychain path must not write the file"
    found = store.get_credential(store.GITHUB_TOKEN)
    assert (found.value, found.source) == (TOKEN, "keychain")
    assert store.delete_credential(store.GITHUB_TOKEN) is True
    assert store.get_credential(store.GITHUB_TOKEN) is None


def test_keychain_failure_falls_back_to_the_file(fake_keyring, monkeypatch):
    def broken(service, key, value):
        raise RuntimeError("no Secret Service available")

    monkeypatch.setattr(fake_keyring, "set_password", broken)
    where = store.set_credential(store.GITHUB_TOKEN, TOKEN)
    assert where == str(store.credentials_file())
    assert store.get_credential(store.GITHUB_TOKEN).value == TOKEN
