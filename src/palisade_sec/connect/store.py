"""Credential storage for the connected surfaces (GitHub, Slack, LLM keys).

Palisade is a security tool, so the rules here are deliberately strict:

- The OS keychain is used when `keyring` is installed (macOS Keychain,
  Windows Credential Manager, Linux Secret Service). Otherwise a file at
  $XDG_CONFIG_HOME/palisade/credentials.toml, created 0600 inside a 0700
  directory, and refused if something else has loosened those permissions.
- The process environment always wins over stored values, so CI keeps
  working without any of this.
- Values are never printed, logged, or written into a report: everything
  user-facing goes through `redact()`.
- Nothing in the offline core (scan, map, baseline, fix) imports this
  module; only the explicitly networked commands do.
"""

from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

SERVICE = "palisade-sec"

# Stored keys. The env var, when set, always takes precedence.
GITHUB_TOKEN = "github.token"
SLACK_WEBHOOK = "slack.webhook"
LLM_PROVIDER = "llm.provider"
LLM_KEY = "llm.key"
LLM_ENDPOINT = "llm.endpoint"
LLM_MODEL = "llm.model"

ENV_OVERRIDE: dict[str, tuple[str, ...]] = {
    GITHUB_TOKEN: ("PALISADE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"),
    SLACK_WEBHOOK: ("PALISADE_SLACK_WEBHOOK",),
    LLM_PROVIDER: ("PALISADE_JUDGE_BACKEND",),
    LLM_KEY: ("TYPESAFE_API_KEY", "ANTHROPIC_API_KEY", "PALISADE_JUDGE_API_KEY"),
    LLM_ENDPOINT: ("PALISADE_JUDGE_ENDPOINT",),
    LLM_MODEL: ("PALISADE_JUDGE_MODEL",),
}

_SECRET_KEYS = frozenset({GITHUB_TOKEN, SLACK_WEBHOOK, LLM_KEY})


class CredentialError(RuntimeError):
    """Storage is unusable or unsafe. Never carries the secret itself."""


@dataclass(frozen=True)
class Resolved:
    """A credential and where it came from, for `palisade-sec connections`."""

    key: str
    value: str
    source: str  # "env:NAME" | "keychain" | "file" | "gh"

    @property
    def display(self) -> str:
        return redact(self.value) if self.key in _SECRET_KEYS else self.value


def redact(value: str | None) -> str:
    """`ghp_abc...wxyz` -> `ghp_…wxyz`. Enough to recognise, useless if leaked."""
    if not value:
        return "-"
    tail = value[-4:] if len(value) > 8 else ""
    head = value[:4] if len(value) > 12 else ""
    return f"{head}…{tail}" if tail else "…"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "palisade"


def credentials_file() -> Path:
    return config_dir() / "credentials.toml"


def _keyring():
    """The keyring module, or None when it is not installed or has no usable
    backend (a headless Linux box without Secret Service, typically)."""
    if os.environ.get("PALISADE_NO_KEYRING"):
        return None
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
    except Exception:  # noqa: BLE001 - any import problem means "use the file"
        return None
    try:
        if isinstance(keyring.get_keyring(), FailKeyring):
            return None
    except Exception:  # noqa: BLE001
        return None
    return keyring


def _read_file() -> dict[str, str]:
    path = credentials_file()
    if not path.is_file():
        return {}
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CredentialError(
            f"{path} is readable by other users (mode {stat.filemode(mode)}). "
            f"Run `chmod 600 {path}` before using stored credentials."
        )
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
        raise CredentialError(f"{path} could not be read: {exc}") from exc
    return {k: str(v) for k, v in data.items() if isinstance(v, str)}


def _write_file(values: dict[str, str]) -> Path:
    path = credentials_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    # Create with 0600 from the start: never a window where the secret is
    # world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("# Written by `palisade-sec connect`. Keep this file private.\n")
        for k in sorted(values):
            fh.write(f'"{k}" = "{values[k]}"\n')
    os.chmod(path, 0o600)
    return path


def set_credential(key: str, value: str) -> str:
    """Store `value`. Returns where it went: "keychain" or the file path."""
    kr = _keyring()
    if kr is not None:
        try:
            kr.set_password(SERVICE, key, value)
            return "keychain"
        except Exception:  # noqa: BLE001 - fall back rather than fail the command
            pass
    values = _read_file()
    values[key] = value
    return str(_write_file(values))


def delete_credential(key: str) -> bool:
    """Remove `key` from every store. True if anything was removed."""
    removed = False
    kr = _keyring()
    if kr is not None:
        try:
            if kr.get_password(SERVICE, key) is not None:
                kr.delete_password(SERVICE, key)
                removed = True
        except Exception:  # noqa: BLE001
            pass
    try:
        values = _read_file()
    except CredentialError:
        values = {}
    if key in values:
        del values[key]
        _write_file(values)
        removed = True
    return removed


def get_credential(key: str) -> Resolved | None:
    """Environment first, then the keychain, then the file."""
    for name in ENV_OVERRIDE.get(key, ()):
        raw = os.environ.get(name, "").strip()
        if raw:
            return Resolved(key, raw, f"env:{name}")
    kr = _keyring()
    if kr is not None:
        try:
            stored = kr.get_password(SERVICE, key)
        except Exception:  # noqa: BLE001
            stored = None
        if stored:
            return Resolved(key, stored, "keychain")
    value = _read_file().get(key)
    return Resolved(key, value, "file") if value else None


def storage_backend() -> str:
    return "OS keychain" if _keyring() is not None else f"file ({credentials_file()})"
