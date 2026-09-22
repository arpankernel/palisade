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


def _load_dotenv() -> None:
    """Load a local .env if python-dotenv is available. Optional: without it,
    the process environment is used as-is."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(override=False)


def get_backend() -> JudgeBackend:
    """Construct the configured backend, or raise JudgeError with a clear,
    key-free message."""
    _load_dotenv()
    name = os.environ.get(BACKEND_ENV, "typesafe").strip().lower()
    if name not in _VALID:
        raise JudgeError(f"{BACKEND_ENV} must be one of {_VALID}, got {name!r}")

    endpoint = os.environ.get(ENDPOINT_ENV, "").strip()
    model = os.environ.get(MODEL_ENV, "").strip()

    if name == "typesafe":
        try:
            from palisade_sec.judge.typesafe import (
                DEFAULT_ENDPOINT,
                DEFAULT_MODEL,
                TypeSafeBackend,
            )
        except ImportError as exc:
            raise JudgeError(MISSING_EXTRA) from exc

        key = os.environ.get(TYPESAFE_KEY_ENV, "").strip()
        if not key:
            raise JudgeError(
                f"{TYPESAFE_KEY_ENV} is not set. Configure it in .env; the judgment "
                "layer sends IR-verified snippets to the endpoint. The offline core "
                "(scan, map, baseline, fix) needs no key."
            )
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

    key = os.environ.get(GENERIC_KEY_ENV, "").strip()
    if not key:
        raise JudgeError(f"{GENERIC_KEY_ENV} is not set (required for {name}).")
    if not endpoint:
        raise JudgeError(f"{ENDPOINT_ENV} is required for {name} (no default).")
    if not model:
        raise JudgeError(f"{MODEL_ENV} is required for {name} (no default).")
    return OpenAICompatibleBackend(api_key=key, endpoint=endpoint, model=model)


def describe(backend: JudgeBackend) -> str:
    """A key-free one-liner for CLI banners."""
    endpoint = getattr(backend, "endpoint", "?")
    model = getattr(backend, "model", "?")
    tag = "calibrated" if backend.verified else "best-effort, unverified"
    return f"{backend.name} ({tag}) · {model} · {endpoint}"
