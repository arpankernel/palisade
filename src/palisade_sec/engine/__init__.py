"""Language-agnostic taint engine. Operates only on the IR - never on a
language-specific AST."""

from palisade_sec.engine.analyzer import Engine
from palisade_sec.engine.findings import Finding, TracePoint
from palisade_sec.engine.taint import PartialHit, Taint

__all__ = ["Engine", "Finding", "PartialHit", "Taint", "TracePoint"]
