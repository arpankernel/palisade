"""Palisade's opt-in semantic layer: the "AI Safety Engineer" tier.

This package is NOT loaded by `palisade-sec scan`. `scan` stays offline,
keyless, and precision-1.000 (see docs/typesafe-integration.md). The semantic
layer is reached only through `palisade-sec audit`/`review`, requires the
optional `palisade-sec[judge]` extra (alias: `[semantic]`) and a judgment
endpoint configured in `.env`, and sends small, IR-verified snippets to that
endpoint. It answers through the `palisade_sec.judge` backends (TypeSafe or a
generic OpenAI-compatible endpoint).

Design invariant: we only ever ask the backend about artifacts the
deterministic IR verified exist (the PROBE). That grounding is what separates
this from a raw-file LLM reviewer that hallucinates.
"""

from palisade_sec.semantic.probe import (
    CapabilityHit,
    ToolArtifact,
    harvest_tools,
)

__all__ = ["CapabilityHit", "ToolArtifact", "harvest_tools"]
