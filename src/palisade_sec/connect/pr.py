"""Open a pull request with the remediation plan, from the terminal.

Everything goes through the GitHub REST API with the connected token: no
local branch, no `git push`, no credential handed to a subprocess. The
branch name is derived from the findings, so re-running updates the same
pull request instead of opening a second one.

What lands in the PR is the `fix` plan: a guardrail and a regression test
per finding, for a human to apply. Palisade does not write the patch
itself - the eval-gated patch engine is deliberately still deferred - and
the PR says so and opens as a draft.
"""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
from dataclasses import dataclass

from palisade_sec.connect.errors import ConnectError
from palisade_sec.connect.http import HttpError, request_json

API = "https://api.github.com"
DEFAULT_PATH = "palisade-fixes.md"


class PrError(ConnectError):
    """A pull-request problem, phrased as what to do next."""


@dataclass(frozen=True)
class Target:
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


_REMOTE_RE = re.compile(
    r"^(?:https://[^/]+/|git@[^:]+:|ssh://git@[^/]+/)(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$"
)


def target_from_remote(cwd: str = ".", remote: str = "origin") -> Target:
    """Parse owner/repo out of a git remote."""
    try:
        r = subprocess.run(
            ["git", "-C", cwd, "remote", "get-url", remote],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PrError(f"could not run git: {exc}") from None
    url = r.stdout.strip()
    if r.returncode != 0 or not url:
        raise PrError(
            f"no git remote {remote!r} here. Run this inside a clone, or pass --repo owner/name."
        )
    m = _REMOTE_RE.match(url)
    if not m:
        raise PrError(f"could not read owner/repo from the {remote} URL. Pass --repo owner/name.")
    return Target(m.group("owner"), m.group("repo"))


def parse_slug(slug: str) -> Target:
    if slug.count("/") != 1 or not all(slug.split("/")):
        raise PrError(f"--repo must look like owner/name, got {slug!r}")
    owner, repo = slug.split("/")
    return Target(owner, repo)


def branch_for(findings: list) -> str:
    """A stable branch name for this exact set of findings, so re-running
    updates one pull request instead of opening another."""
    digest = hashlib.sha256("|".join(sorted(f.fingerprint for f in findings)).encode())
    return f"palisade/fix-{digest.hexdigest()[:8]}"


class GitHubRepo:
    """The few REST calls this needs, with errors worth reading."""

    def __init__(self, token: str, target: Target, request=request_json) -> None:
        self._token = token
        self.target = target
        self._request = request

    def _call(self, path: str, *, method: str = "GET", body: dict | None = None) -> dict:
        data, _headers = self._request(
            f"{API}{path}",
            method=method,
            body=body,
            headers={
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        return dict(data)

    def info(self) -> dict:
        try:
            return self._call(f"/repos/{self.target.slug}")
        except HttpError as exc:
            if exc.status == 404:
                raise PrError(
                    f"{self.target.slug} not found, or the connected token cannot see it. "
                    "A fine-grained token needs access to this repository."
                ) from None
            if exc.status in (401, 403):
                raise PrError(
                    "GitHub refused the connected token. Re-run `palisade-sec connect github`."
                ) from None
            raise PrError(f"could not read {self.target.slug}: {exc}") from None

    def head_sha(self, branch: str) -> str | None:
        try:
            ref = self._call(f"/repos/{self.target.slug}/git/ref/heads/{branch}")
        except HttpError as exc:
            if exc.status == 404:
                return None
            raise PrError(f"could not read branch {branch}: {exc}") from None
        obj = ref.get("object") or {}
        return str(obj.get("sha")) if obj.get("sha") else None

    def create_branch(self, branch: str, from_sha: str) -> None:
        try:
            self._call(
                f"/repos/{self.target.slug}/git/refs",
                method="POST",
                body={"ref": f"refs/heads/{branch}", "sha": from_sha},
            )
        except HttpError as exc:
            if exc.status == 403:
                raise PrError(
                    "the connected token cannot write to this repository (403). It needs "
                    "`repo` scope, or Contents: write on a fine-grained token."
                ) from None
            raise PrError(f"could not create branch {branch}: {exc}") from None

    def file_sha(self, path: str, branch: str) -> str | None:
        try:
            data = self._call(f"/repos/{self.target.slug}/contents/{path}?ref={branch}")
        except HttpError as exc:
            if exc.status == 404:
                return None
            raise PrError(f"could not read {path}: {exc}") from None
        return str(data.get("sha")) if data.get("sha") else None

    def put_file(self, path: str, branch: str, content: str, message: str) -> None:
        body: dict = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        existing = self.file_sha(path, branch)
        if existing:
            body["sha"] = existing
        try:
            self._call(f"/repos/{self.target.slug}/contents/{path}", method="PUT", body=body)
        except HttpError as exc:
            raise PrError(f"could not write {path}: {exc}") from None

    def open_pr(self, *, head: str, base: str, title: str, body: str, draft: bool) -> dict:
        try:
            return self._call(
                f"/repos/{self.target.slug}/pulls",
                method="POST",
                body={"title": title, "head": head, "base": base, "body": body, "draft": draft},
            )
        except HttpError as exc:
            raise PrError(f"could not open the pull request: {exc}") from None

    def existing_pr(self, head: str) -> dict | None:
        try:
            data, _ = self._request(
                f"{API}/repos/{self.target.slug}/pulls?head={self.target.owner}:{head}&state=open",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        except HttpError:
            return None
        items = data.get("data") if isinstance(data.get("data"), list) else None
        if items is None:
            items = data if isinstance(data, list) else []
        return items[0] if items else None


def pr_body(findings: list, files_scanned: int, plan_path: str) -> str:
    """The PR description. States plainly that this is a plan to review."""
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "med")
    lines = [
        f"Palisade found **{high} high** and **{med} med** prompt-injection "
        f"path(s) across {files_scanned} scanned file(s).",
        "",
        "| Rule | Location | Maps to |",
        "|---|---|---|",
    ]
    for f in findings[:20]:
        maps = ", ".join(f.owasp_llm) if f.owasp_llm else ""
        lines.append(f"| `{f.rule_id}` | `{f.file}:{f.line}` | {maps} |")
    if len(findings) > 20:
        lines.append(f"| … | {len(findings) - 20} more | |")
    lines += [
        "",
        f"`{plan_path}` in this branch has, for each finding, a guardrail and a "
        "regression test that proves the guardrail blocks the attack and keeps "
        "the happy path working.",
        "",
        "**This is a plan, not a patch.** Palisade does not edit your source: "
        "apply the guardrails where they belong, adapt the allowlists, and keep "
        "the tests. That is why this PR opens as a draft.",
        "",
        "<sub>Opened by `palisade-sec pr`. Re-running updates this same PR.</sub>",
    ]
    return "\n".join(lines)
