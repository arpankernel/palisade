"""JUDGE: turn grounded artifacts into calibrated typed judgments via TypeSafe.

The `Judge` protocol is the seam that keeps the audit testable offline: the
test suite drives `audit` with a `FakeJudge` and makes zero network calls.
`TypeSafeJudge` is the real implementation, reached only through
`palisade-sec audit` with the `[semantic]` extra installed and a key set.

Docs: https://docs.typesafe.ai/sdk/python.md , /primitives/noul.md , /primitives/score.md
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from palisade_sec.semantic.policy import CheckPolicy
from palisade_sec.semantic.probe import ToolArtifact

API_KEY_ENV = "TYPESAFE_API_KEY"

# Score levels for the excessive-agency harm question (0-3), mirroring the
# llm_guardrails cookbook harm scale.
HARM_LEVELS: dict[str, str] = {
    "none": "No real-world effect; read-only or purely computational.",
    "moderate": "Reversible or low-impact side effects (e.g. writes a temp file).",
    "high": "Significant, hard-to-reverse effects (deletes data, sends external messages).",
    "severe": "Catastrophic or unrecoverable (runs arbitrary shell, spends money, destroys prod).",
}


@dataclass
class Judgment:
    """The calibrated answer for the excessive-agency check."""

    irreversible: float  # P(tool can take an irreversible/destructive action)
    gated: float  # P(tool requires human confirmation before that action)
    harm: int  # 0-3 harm if a manipulated model invokes it
    notes: str = ""


class Judge(Protocol):
    def judge_excessive_agency(
        self, artifact: ToolArtifact, policy: CheckPolicy
    ) -> Judgment: ...


def _artifact_state(artifact: ToolArtifact) -> dict:
    """Only IR-verified facts leave the machine. Nothing else."""
    return {
        "tool_name": artifact.name,
        "stated_purpose": artifact.docstring or "(none stated)",
        "capabilities_detected": artifact.capabilities,
        "dangerous_call_sites": [
            f"{h.func_path}  ->  {h.snippet}" for h in artifact.capability_hits
        ],
    }


class TypeSafeJudge:
    """Real TypeSafe-backed judge. Imports the SDK lazily so the package only
    needs it when `audit` actually runs."""

    def __init__(self) -> None:
        try:
            from typesafe_sdk import TypeSafeClient  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised via CLI
            raise RuntimeError(
                "the semantic layer needs the TypeSafe SDK: "
                "pip install 'palisade-sec[semantic]'"
            ) from exc
        if not os.environ.get(API_KEY_ENV):
            raise RuntimeError(
                f"{API_KEY_ENV} is not set. Get a key at https://console.typesafe.ai "
                "and export it; `audit` sends code snippets to TypeSafe."
            )
        self._TypeSafeClient = TypeSafeClient

    def judge_excessive_agency(
        self, artifact: ToolArtifact, policy: CheckPolicy
    ) -> Judgment:  # pragma: no cover - requires live API
        from typesafe_sdk import Noul, Score

        irreversible_desc = policy.criteria.get(
            "irreversible",
            "takes an action that cannot be undone or has real-world consequences",
        )
        with self._TypeSafeClient() as client:
            resp = client.system_one(
                state=_artifact_state(artifact),
                questions={
                    "irreversible": Noul(
                        instructions=(
                            "This function is a tool an AI model can choose to call. "
                            "Considering `dangerous_call_sites`, can invoking it take an "
                            "irreversible or destructive action - specifically one that "
                            f"{irreversible_desc}? Renaming, logging, or pure computation "
                            "do NOT count."
                        )
                    ),
                    "gated": Noul(
                        instructions=(
                            "Does this tool require explicit human confirmation or "
                            "approval before performing its action (e.g. a confirm step, "
                            "an allowlist check that can raise, a dry-run flag)?"
                        )
                    ),
                    "harm": Score(
                        instructions=(
                            "If a prompt-injected / manipulated model invoked this tool "
                            "with attacker-chosen arguments, how much harm could result?"
                        ),
                        criteria=HARM_LEVELS,
                    ),
                },
            )
        return Judgment(
            irreversible=float(resp.nouls["irreversible"].noul),
            gated=float(resp.nouls["gated"].noul),
            harm=int(round(float(resp.scores["harm"].score))),
        )


def get_judge() -> Judge:
    """Return a live judge or raise a friendly, actionable error."""
    return TypeSafeJudge()
