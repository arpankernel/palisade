"""GitHub connection: reuse the `gh` CLI's token, or run the OAuth device flow.

Resolution order for every command that needs GitHub (`palisade-sec pr`):

    1. the environment (PALISADE_GITHUB_TOKEN / GITHUB_TOKEN / GH_TOKEN) -
       this is what CI uses, so nothing has to be "connected" there;
    2. a token stored by `palisade-sec connect github`;
    3. the `gh` CLI's own token, if gh is installed and logged in.

The device flow needs a GitHub OAuth App client id. It is public (it is not a
secret), but it has to be registered once for this project; until then, the
`gh` path and `--token` cover everyone.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass

from palisade_sec.connect.errors import ConnectError
from palisade_sec.connect.http import HttpError, post_form, request_json
from palisade_sec.connect.store import GITHUB_TOKEN, Resolved, get_credential

API = "https://api.github.com"
DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"

# Public OAuth App client id. Set PALISADE_GITHUB_CLIENT_ID to override, or
# fill this in once the OAuth App is registered.
CLIENT_ID = os.environ.get("PALISADE_GITHUB_CLIENT_ID", "").strip()

# Least privilege for opening a pull request from a fork-less branch.
SCOPES = "repo"


class GitHubError(ConnectError):
    """A GitHub problem stated in terms of what the user should do next."""


@dataclass(frozen=True)
class Identity:
    login: str
    scopes: list[str]
    source: str


def gh_cli_token() -> str | None:
    """The `gh` CLI's token, if gh is installed and logged in."""
    try:
        r = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    token = r.stdout.strip()
    return token or None


def resolve_token() -> Resolved | None:
    stored = get_credential(GITHUB_TOKEN)
    if stored:
        return stored
    token = gh_cli_token()
    return Resolved(GITHUB_TOKEN, token, "gh") if token else None


def verify(token: str, source: str = "?") -> Identity:
    """Confirm the token works and report who it is and what it can do."""
    try:
        data, headers = request_json(
            f"{API}/user",
            headers={"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"},
        )
    except HttpError as exc:
        if exc.status == 401:
            raise GitHubError(
                "GitHub rejected that token (401). It may be expired or revoked."
            ) from None
        raise GitHubError(f"could not verify the token: {exc}") from None
    login = str(data.get("login") or "?")
    raw = headers.get("X-OAuth-Scopes") or headers.get("x-oauth-scopes") or ""
    scopes = [s.strip() for s in raw.split(",") if s.strip()]
    return Identity(login=login, scopes=scopes, source=source)


def can_open_prs(identity: Identity) -> bool:
    """A classic token needs `repo` (or `public_repo`). Fine-grained tokens
    report no scopes at all, so they are accepted and checked at use time."""
    if not identity.scopes:
        return True  # fine-grained or a GitHub App token: permissions are per-repo
    return any(s in identity.scopes for s in ("repo", "public_repo"))


@dataclass
class DeviceCode:
    user_code: str
    verification_uri: str
    device_code: str
    interval: int
    expires_in: int


def start_device_flow(client_id: str = "") -> DeviceCode:
    cid = client_id or CLIENT_ID
    if not cid:
        raise GitHubError(
            "the OAuth device flow is not configured for this build. Use `gh auth login` "
            "and re-run `palisade-sec connect github`, or pass a token with --token. "
            "(Maintainers: register a GitHub OAuth App and set PALISADE_GITHUB_CLIENT_ID.)"
        )
    data = post_form(DEVICE_CODE_URL, {"client_id": cid, "scope": SCOPES})
    if "device_code" not in data:
        raise GitHubError(f"GitHub did not start a device flow: {data.get('error', 'unknown')}")
    return DeviceCode(
        user_code=str(data["user_code"]),
        verification_uri=str(data.get("verification_uri", "https://github.com/login/device")),
        device_code=str(data["device_code"]),
        interval=int(data.get("interval", 5)),
        expires_in=int(data.get("expires_in", 900)),
    )


def poll_device_flow(code: DeviceCode, client_id: str = "", sleep=time.sleep) -> str:
    """Wait for the user to approve in the browser; returns the access token."""
    cid = client_id or CLIENT_ID
    deadline = time.monotonic() + code.expires_in
    interval = code.interval
    while time.monotonic() < deadline:
        sleep(interval)
        data = post_form(
            ACCESS_TOKEN_URL,
            {
                "client_id": cid,
                "device_code": code.device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )
        token = data.get("access_token")
        if token:
            return str(token)
        error = data.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval = int(data.get("interval", interval + 5))
            continue
        if error == "expired_token":
            raise GitHubError("the device code expired before it was approved. Try again.")
        if error == "access_denied":
            raise GitHubError("the request was denied in the browser.")
        raise GitHubError(f"device flow failed: {error or 'unknown error'}")
    raise GitHubError("timed out waiting for approval in the browser.")
