"""The excessive-agency check's judgment spec.

This is not a backend; it is the *questions* the check asks and how it reads the
answers. Any `JudgeBackend` (TypeSafe or generic OpenAI-compatible) can answer
them. The state passed in is built only from IR-verified facts about a tool the
PROBE found, so the judgment stays grounded (principle 3).

Docs: https://docs.typesafe.ai/primitives/noul.md , /primitives/score.md
"""

from __future__ import annotations

from dataclasses import dataclass

from palisade_sec.judge.types import JudgeResult, NoulQ, Question, ScoreQ
from palisade_sec.semantic.policy import CheckPolicy
from palisade_sec.semantic.probe import ToolArtifact

# Ordered harm levels (index = score 0..3), mirroring the llm_guardrails scale.
HARM_LEVELS: list[str] = [
    "No real-world effect; read-only or purely computational.",
    "Reversible or low-impact side effects (e.g. writes a temp file).",
    "Significant, hard-to-reverse effects (deletes data, sends external messages).",
    "Catastrophic or unrecoverable (runs arbitrary shell, spends money, destroys prod).",
]


@dataclass
class Judgment:
    """The calibrated answer for the excessive-agency check."""

    irreversible: float  # P(tool can take an irreversible/destructive action)
    gated: float  # P(tool requires human confirmation before that action)
    harm: int  # 0-3 harm if a manipulated model invokes it


def excessive_agency_state(artifact: ToolArtifact) -> dict:
    """Only IR-verified facts leave the machine. Nothing else."""
    return {
        "tool_name": artifact.name,
        "stated_purpose": artifact.docstring or "(none stated)",
        "capabilities_detected": artifact.capabilities,
        "dangerous_call_sites": [
            f"{h.func_path}  ->  {h.snippet}" for h in artifact.capability_hits
        ],
    }


def excessive_agency_questions(policy: CheckPolicy) -> list[Question]:
    irreversible_desc = policy.criteria.get(
        "irreversible",
        "takes an action that cannot be undone or has real-world consequences",
    )
    return [
        NoulQ(
            id="irreversible",
            instructions=(
                "This function is a tool an AI model can choose to call. Considering "
                "`dangerous_call_sites`, can invoking it take an irreversible or "
                f"destructive action - specifically one that {irreversible_desc}? "
                "Renaming, logging, or pure computation do NOT count."
            ),
        ),
        NoulQ(
            id="gated",
            instructions=(
                "Does this tool require explicit human confirmation or approval before "
                "performing its action (e.g. a confirm step, an allowlist check that can "
                "raise, a dry-run flag)?"
            ),
        ),
        ScoreQ(
            id="harm",
            instructions=(
                "If a prompt-injected / manipulated model invoked this tool with "
                "attacker-chosen arguments, how much harm could result?"
            ),
            levels=HARM_LEVELS,
        ),
    ]


def interpret(result: JudgeResult) -> Judgment:
    return Judgment(
        irreversible=result.noul("irreversible"),
        gated=result.noul("gated"),
        harm=int(round(result.score("harm"))),
    )
