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
import re
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

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _flat(output: str) -> str:
    """CLI output as plain words: rich adds colour in CI and wraps errors into
    a box, so tests compare meaning, not presentation."""
    text = _ANSI.sub("", output)
    for ch in "\u2502\u2503\u250a\u254e":  # box verticals
        text = text.replace(ch, " ")
    return " ".join(text.split())


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
    assert "needs `repo`" in _flat(result.output), result.output
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


# ---------------------------------------------------------------------------
# palisade-sec pr
# ---------------------------------------------------------------------------

VULN_APP = (
    "from flask import request\n"
    "from openai import OpenAI\n"
    "client = OpenAI()\n"
    "import os\n"
    "def h():\n"
    "    q = request.json['q']\n"
    "    r = client.chat.completions.create(messages=[{'role':'user','content':q}])\n"
    "    os.system(r.choices[0].message.content)\n"
)


class _FakeGitHub:
    """Records the API calls `pr` makes, so the flow can be asserted."""

    def __init__(self, *, branch_exists=False, open_pr=None):
        self.calls: list[tuple[str, str]] = []
        self.written: dict[str, str] = {}
        self.branch_exists = branch_exists
        self.open_pr = open_pr
        self.created_branch: str | None = None

    def __call__(self, url, *, method="GET", body=None, headers=None, timeout=30.0):
        import base64 as _b64

        path = url.split("api.github.com")[-1]
        self.calls.append((method, path))
        if path.endswith("/palisade") and method == "GET":
            return {"default_branch": "main"}, {}
        if "/git/ref/heads/main" in path:
            return {"object": {"sha": "basesha"}}, {}
        if "/git/ref/heads/palisade/" in path:
            if self.branch_exists:
                return {"object": {"sha": "headsha"}}, {}
            raise HttpError(404, "Not Found")
        if "/git/refs" in path and method == "POST":
            self.created_branch = body["ref"]
            return {}, {}
        if "/contents/" in path and method == "GET":
            raise HttpError(404, "Not Found")
        if "/contents/" in path and method == "PUT":
            self.written[path.split("/contents/")[1]] = _b64.b64decode(body["content"]).decode()
            return {"commit": {"sha": "c1"}}, {}
        if "/pulls?" in path:
            return ({"data": [self.open_pr]} if self.open_pr else {"data": []}), {}
        if path.endswith("/pulls") and method == "POST":
            self.draft = body["draft"]
            self.title = body["title"]
            self.body = body["body"]
            return {"html_url": "https://github.com/arpankernel/palisade/pull/99"}, {}
        raise AssertionError(f"unexpected call {method} {path}")


@pytest.fixture
def repo_with_finding(tmp_path):
    (tmp_path / "app.py").write_text(VULN_APP)
    return tmp_path


def _patch_api(monkeypatch, fake):
    from palisade_sec.connect import pr as pr_mod

    original = pr_mod.GitHubRepo.__init__

    def init(self, token, target, request=None):
        original(self, token, target, request=fake)

    monkeypatch.setattr(pr_mod.GitHubRepo, "__init__", init)


def test_pr_opens_a_draft_with_the_plan(isolated_store, repo_with_finding, monkeypatch):
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    fake = _FakeGitHub()
    _patch_api(monkeypatch, fake)
    result = runner.invoke(app, ["pr", str(repo_with_finding), "--repo", "arpankernel/palisade"])
    assert result.exit_code == 0, result.output
    assert "pull/99" in result.output
    assert fake.created_branch.startswith("refs/heads/palisade/fix-")
    assert fake.draft is True, "an unreviewed plan must open as a draft"
    plan = fake.written["palisade-fixes.md"]
    assert "PI-SHELL" in plan and "def test_" in plan, "the plan carries guardrail + test"
    assert "plan, not a patch" in fake.body


def test_pr_is_idempotent(isolated_store, repo_with_finding, monkeypatch):
    """Re-running must update the existing PR, never open a second one."""
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    existing = {"html_url": "https://github.com/arpankernel/palisade/pull/42"}
    fake = _FakeGitHub(branch_exists=True, open_pr=existing)
    _patch_api(monkeypatch, fake)
    result = runner.invoke(app, ["pr", str(repo_with_finding), "--repo", "arpankernel/palisade"])
    assert result.exit_code == 0, result.output
    assert "pull/42" in result.output
    assert not any(m == "POST" and p.endswith("/pulls") for m, p in fake.calls)
    assert fake.created_branch is None, "the branch already existed"


def test_pr_branch_name_is_stable_for_the_same_findings(repo_with_finding):
    from palisade_sec.connect import pr as pr_mod
    from palisade_sec.scanner import run_scan

    first = pr_mod.branch_for(run_scan(repo_with_finding).findings)
    second = pr_mod.branch_for(run_scan(repo_with_finding).findings)
    assert first == second and first.startswith("palisade/fix-")


def test_pr_without_a_token_changes_nothing(isolated_store, repo_with_finding, monkeypatch):
    fake = _FakeGitHub()
    _patch_api(monkeypatch, fake)
    result = runner.invoke(app, ["pr", str(repo_with_finding), "--repo", "arpankernel/palisade"])
    assert result.exit_code == 2
    assert "connect github" in result.output
    assert fake.calls == [], "nothing may be sent to GitHub without a token"


def test_pr_on_a_clean_project_opens_nothing(isolated_store, tmp_path, monkeypatch):
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    fake = _FakeGitHub()
    _patch_api(monkeypatch, fake)
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    result = runner.invoke(app, ["pr", str(tmp_path), "--repo", "arpankernel/palisade"])
    assert result.exit_code == 0
    assert "nothing to open" in result.output
    assert fake.calls == []


def test_pr_dry_run_contacts_nobody(isolated_store, repo_with_finding, monkeypatch):
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    fake = _FakeGitHub()
    _patch_api(monkeypatch, fake)
    result = runner.invoke(
        app, ["pr", str(repo_with_finding), "--repo", "arpankernel/palisade", "--dry-run"]
    )
    assert result.exit_code == 0
    assert "dry run" in result.output
    assert fake.calls == []


def test_pr_dry_run_says_where_the_token_came_from(isolated_store, repo_with_finding, monkeypatch):
    """Resolution order is the thing people get wrong ("why is it using my
    old token?"), so the dry run names the source it would use."""
    store.set_credential(store.GITHUB_TOKEN, TOKEN)
    _patch_api(monkeypatch, _FakeGitHub())
    result = runner.invoke(
        app, ["pr", str(repo_with_finding), "--repo", "arpankernel/palisade", "--dry-run"]
    )
    assert "github: connected (via file)" in _flat(result.output)


def test_pr_dry_run_fails_when_github_is_not_connected(
    isolated_store, repo_with_finding, monkeypatch
):
    """A dry run is a pre-flight. Reporting success for a real run that
    cannot even start makes it worse than useless, so it exits 2 - while
    still contacting nobody, because resolving a token is all local."""
    fake = _FakeGitHub()
    _patch_api(monkeypatch, fake)
    result = runner.invoke(
        app, ["pr", str(repo_with_finding), "--repo", "arpankernel/palisade", "--dry-run"]
    )
    flat = _flat(result.output)
    assert result.exit_code == 2
    assert "NOT CONNECTED" in flat
    assert "connect github" in flat
    assert fake.calls == [], "a dry run must not reach GitHub, even to report a failure"


@pytest.mark.parametrize(
    ("url", "slug"),
    [
        ("https://github.com/arpankernel/palisade.git", "arpankernel/palisade"),
        ("git@github.com:arpankernel/palisade.git", "arpankernel/palisade"),
        ("ssh://git@github.com/arpankernel/palisade", "arpankernel/palisade"),
    ],
)
def test_remote_url_parsing(url, slug, tmp_path):
    from palisade_sec.connect import pr as pr_mod

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", url], check=True)
    assert pr_mod.target_from_remote(str(tmp_path)).slug == slug


def test_a_403_says_what_permission_is_missing(monkeypatch):
    from palisade_sec.connect import pr as pr_mod

    def deny(url, **kw):
        raise HttpError(403, "HTTP 403: Resource not accessible")

    api = pr_mod.GitHubRepo("t", pr_mod.Target("o", "r"), request=deny)
    with pytest.raises(pr_mod.PrError) as exc:
        api.create_branch("b", "sha")
    assert "Contents: write" in str(exc.value)
