"""Taint values tracked by the engine.

A taint is immutable and carries its own provenance (where the untrusted
source was read, where the LLM call happened) so a finding can print the
full data-flow trace without a separate path reconstruction pass.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

SOURCE = "source"
LLM = "llm"


@dataclass(frozen=True)
class PartialHit:
    """A partial defense (denylist / confirmation gate) seen on the path.

    Partial defenses do NOT suppress a finding — they downgrade it to MED
    "risky". Real CVEs were exploited despite exactly these defenses.
    """

    pattern: str
    file: str
    line: int


@dataclass(frozen=True)
class Taint:
    kind: str  # SOURCE or LLM
    src_pattern: str
    src_file: str
    src_line: int
    src_snippet: str
    llm_pattern: str = ""
    llm_file: str = ""
    llm_line: int = 0
    llm_snippet: str = ""
    hops: int = 0
    partials: tuple[PartialHit, ...] = ()


TaintSet = frozenset  # frozenset[Taint]
EMPTY: TaintSet = frozenset()


def union(*sets: TaintSet) -> TaintSet:
    out: set[Taint] = set()
    for s in sets:
        out |= s
    return frozenset(out)


def with_partial(ts: TaintSet, hit: PartialHit) -> TaintSet:
    return frozenset(replace(t, partials=tuple(dict.fromkeys((*t.partials, hit)))) for t in ts)


def bump_hops(ts: TaintSet) -> TaintSet:
    return frozenset(replace(t, hops=t.hops + 1) for t in ts)
