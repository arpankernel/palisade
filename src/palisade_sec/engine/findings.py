"""Finding model + fingerprinting.

Fingerprints are line-number independent (rule id + files + normalized code
snippets) so refactors that only shift lines do not churn the baseline (BL-1).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from palisade_sec.engine.taint import PartialHit

SEVERITY_ORDER = {"high": 0, "med": 1, "low": 2}
CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass(frozen=True)
class TracePoint:
    file: str
    line: int
    snippet: str
    detail: str = ""  # the matched pattern / call path


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # high | med | low
    confidence: str  # HIGH | MEDIUM | LOW
    source: TracePoint
    llm: TracePoint
    sink: TracePoint
    partial_defenses: list[PartialHit] = field(default_factory=list)
    attack: str = ""
    fix: str = ""
    references: list[str] = field(default_factory=list)
    count: int = 1

    @property
    def file(self) -> str:
        return self.sink.file

    @property
    def line(self) -> int:
        return self.sink.line

    @property
    def risky(self) -> bool:
        return bool(self.partial_defenses)

    @property
    def fingerprint(self) -> str:
        def norm(s: str) -> str:
            return " ".join(s.split())

        payload = "|".join(
            [
                self.rule_id,
                self.source.file,
                norm(self.source.snippet),
                self.sink.file,
                norm(self.sink.snippet),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def sort_key(self) -> tuple:
        return (
            SEVERITY_ORDER.get(self.severity, 9),
            self.file,
            self.line,
            self.rule_id,
        )

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "risky_partial_defense": self.risky,
            "file": self.file,
            "line": self.line,
            "fingerprint": self.fingerprint,
            "count": self.count,
            "trace": {
                "source": {
                    "file": self.source.file,
                    "line": self.source.line,
                    "snippet": self.source.snippet,
                    "matched": self.source.detail,
                },
                "llm": {
                    "file": self.llm.file,
                    "line": self.llm.line,
                    "snippet": self.llm.snippet,
                    "matched": self.llm.detail,
                },
                "sink": {
                    "file": self.sink.file,
                    "line": self.sink.line,
                    "snippet": self.sink.snippet,
                    "matched": self.sink.detail,
                },
            },
            "partial_defenses": [
                {"pattern": p.pattern, "file": p.file, "line": p.line}
                for p in self.partial_defenses
            ],
            "attack": self.attack.strip(),
            "fix": self.fix.strip(),
            "references": self.references,
        }
