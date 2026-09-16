"""Pydantic schema for Palisade YAML rules.

Rules are pure data. They declare what to match in the (language-agnostic)
IR: untrusted sources, LLM call signatures, dangerous sinks, sanitizers that
suppress a finding, and partial defenses that downgrade it to MED "risky".
New rules require zero engine changes.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PatternSpec(BaseModel):
    """A set of dotted-path patterns to match against IR call/attribute paths.

    Pattern semantics (strict categories: sources, llm_signatures, sinks):
      - "exec"                    -> exact full-path match only
      - "request.json"            -> exact, or dotted-suffix ("flask.request.json")
      - "*.execute"               -> any path whose final segments match "execute"
                                     with at least one leading segment

    Defense categories (sanitizers, partial_defenses) match leniently:
    the pattern is a case-insensitive substring of the full dotted path.
    """

    model_config = ConfigDict(extra="forbid")

    # "decorator" (sources only): functions decorated with a matching path
    # (e.g. "*.post" for FastAPI routes) are entry points whose parameters
    # are untrusted. Never matched against expression paths.
    kind: Literal["call", "attribute", "name", "decorator"] = "call"
    patterns: list[str] = Field(min_length=1)
    # Sink-only options:
    require_kwargs: dict[str, bool | str | int] | None = None  # e.g. {shell: true}
    safe_if_extra_args: bool = False  # parameterized SQL: execute(q, params) is safe
    # Which positional args are dangerous. None = any argument. [0] for
    # exec/eval & co: exec(code, globals(), locals()) is only exploitable
    # through the CODE argument - a tainted environment dict is not.
    taint_args: list[int] | None = None
    # Sanitizer-only option: trusted sanitizers (known validation frameworks
    # like pydantic model_validate) fully suppress on a name match. Untrusted
    # (name-heuristic) sanitizer matches suppress only when the resolved
    # project-local function body shows a real allowlist/validation shape;
    # otherwise the finding is downgraded to MED "unverified sanitizer".
    trusted: bool = False


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,31}$")
    title: str
    severity: Literal["high", "med", "low"]
    description: str
    sources: list[PatternSpec] = Field(default_factory=list)
    llm_signatures: list[PatternSpec] = Field(min_length=1)
    sinks: list[PatternSpec] = Field(min_length=1)
    sanitizers: list[PatternSpec] = Field(default_factory=list)
    partial_defenses: list[PatternSpec] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    attack: str = ""
    fix: str = ""


def match_strict(path: str, pattern: str) -> bool:
    """Match for sources / llm signatures / sinks. Precision over recall."""
    if not path:
        return False
    if pattern.startswith("*."):
        tail = pattern[2:]
        return path != tail and (path == tail or path.endswith("." + tail))
    if "." in pattern:
        return path == pattern or path.endswith("." + pattern)
    return path == pattern


def match_any_strict(path: str, specs: list[PatternSpec]) -> PatternSpec | None:
    for spec in specs:
        for pat in spec.patterns:
            if match_strict(path, pat):
                return spec
    return None


def match_lenient(path: str, specs: list[PatternSpec]) -> str | None:
    """Match for sanitizers / partial defenses: case-insensitive substring."""
    hit = match_lenient_spec(path, specs)
    return hit[0] if hit else None


def match_lenient_spec(path: str, specs: list[PatternSpec]) -> tuple[str, PatternSpec] | None:
    """Like match_lenient but also returns the matching spec (for `trusted`).
    Trusted specs win over untrusted ones when both match."""
    if not path:
        return None
    low = path.lower()
    fallback: tuple[str, PatternSpec] | None = None
    for spec in specs:
        for pat in spec.patterns:
            if pat.lower() in low:
                if spec.trusted:
                    return pat, spec
                fallback = fallback or (pat, spec)
    return fallback
