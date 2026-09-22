"""Backend selection from the environment (.env).

The offline core never imports this. `get_backend()` reads the environment,
picks an adapter, and constructs it. Keys are read from env only and are never
returned, logged, or included in error text; errors name the missing variable,
not its value.
"""

from __future__ import annotations

import os

from palisade_sec.judge.base import JudgeBackend, JudgeError

BACKEND_ENV = "PALISADE_JUDGE_BACKEND"
ENDPOINT_ENV = "PALISADE_JUDGE_ENDPOINT"
MODEL_ENV = "PALISADE_JUDGE_MODEL"
TYPESAFE_KEY_ENV = "TYPESAFE_API_KEY"
GENERIC_KEY_ENV = "PALISADE_JUDGE_API_KEY"

_VALID = ("typesafe", "openai_compatible")

# Shown when the judgment layer's optional dependencies are missing. The
# offline core ships without them on purpose, so a plain `pip install
# palisade-sec` (or `uvx palisade-sec`) must get this message, never an
# ImportError traceback.
MISSING_EXTRA = (
    "the judgment layer needs the optional `judge` extra, which is not installed. "
    "Install it with `pip install 'palisade-sec[judge]'` "
    "(or run `uvx --from 'palisade-sec[judge]' palisade-sec ...`). "
    "The offline core (scan, map, baseline, fix) needs neither the extra nor a key."
)


def _dotenv_values() -> dict[str, str]:
    """Values from a `.env` in the current working directory (or a parent),
    if python-dotenv is available. Never written into os.environ."""
    try:
        from dotenv import dotenv_values, find_dotenv
    except ImportError:
        return {}
    path = find_dotenv(usecwd=True)
    if not path:
        return {}
    return {k: v for k, v in dotenv_values(path).items() if v is not None}


def _resolve_env() -> tuple[dict[str, str], set[str]]:
    """The judge settings, and which of them came from a `.env` file.

    The process environment wins over `.env` for every variable. `.env` is
    read from the current directory because that is where the docs tell users
    to put it; 0.5.0 searched from the installed package's folder instead, so
    a `.env` was silently ignored for every pip/uvx install.
    """
    names = (BACKEND_ENV, ENDPOINT_ENV, MODEL_ENV, TYPESAFE_KEY_ENV, GENERIC_KEY_ENV)
    dotenv = _dotenv_values()
    env: dict[str, str] = {}
    from_file: set[str] = set()
    for n in names:
        if os.environ.get(n, "").strip():
            env[n] = os.environ[n]
        elif dotenv.get(n, "").strip():
            env[n] = dotenv[n]
            from_file.add(n)
    return env, from_file


def _refuse_split_origin(from_file: set[str], key_env: str) -> None:
    """Refuse an endpoint from `.env` paired with a key from the shell.

    Palisade is run inside repositories it does not trust. A cloned repo can
    ship a `.env` that points the judge at an attacker's server; if the user's
    real API key lives in their shell environment, it would be sent there as
    an Authorization header. Endpoint and key must come from the same place.
    """
    if (ENDPOINT_ENV in from_file or BACKEND_ENV in from_file) and key_env not in from_file:
        raise JudgeError(
            f"refusing to send your {key_env} from the shell environment to an endpoint "
            f"chosen by a .env file in this directory. A repository you did not write "
            f"can ship that file. Set {ENDPOINT_ENV} in your shell too, or put the key "
            "in the same .env."
        )


def get_backend() -> JudgeBackend:
    """Construct the configured backend, or raise JudgeError with a clear,
    key-free message."""
    env, from_file = _resolve_env()
    name = env.get(BACKEND_ENV, "typesafe").strip().lower()
    if name not in _VALID:
        raise JudgeError(f"{BACKEND_ENV} must be one of {_VALID}, got {name!r}")

    endpoint = env.get(ENDPOINT_ENV, "").strip()
    model = env.get(MODEL_ENV, "").strip()

    if name == "typesafe":
        try:
            from palisade_sec.judge.typesafe import (
                DEFAULT_ENDPOINT,
                DEFAULT_MODEL,
                TypeSafeBackend,
            )
        except ImportError as exc:
            raise JudgeError(MISSING_EXTRA) from exc

        key = env.get(TYPESAFE_KEY_ENV, "").strip()
        if not key:
            raise JudgeError(
                f"{TYPESAFE_KEY_ENV} is not set. Configure it in .env; the judgment "
                "layer sends IR-verified snippets to the endpoint. The offline core "
                "(scan, map, baseline, fix) needs no key."
            )
        _refuse_split_origin(from_file, TYPESAFE_KEY_ENV)
        return TypeSafeBackend(
            api_key=key,
            endpoint=endpoint or DEFAULT_ENDPOINT,
            model=model or DEFAULT_MODEL,
        )

    # openai_compatible
    try:
        from palisade_sec.judge.openai_compatible import OpenAICompatibleBackend
    except ImportError as exc:
        raise JudgeError(MISSING_EXTRA) from exc

    key = env.get(GENERIC_KEY_ENV, "").strip()
    if not key:
        raise JudgeError(f"{GENERIC_KEY_ENV} is not set (required for {name}).")
    if not endpoint:
        raise JudgeError(f"{ENDPOINT_ENV} is required for {name} (no default).")
    if not model:
        raise JudgeError(f"{MODEL_ENV} is required for {name} (no default).")
    _refuse_split_origin(from_file, GENERIC_KEY_ENV)
    return OpenAICompatibleBackend(api_key=key, endpoint=endpoint, model=model)


def describe(backend: JudgeBackend) -> str:
    """A key-free one-liner for CLI banners."""
    endpoint = getattr(backend, "endpoint", "?")
    model = getattr(backend, "model", "?")
    tag = "calibrated" if backend.verified else "best-effort, unverified"
    return f"{backend.name} ({tag}) · {model} · {endpoint}"
