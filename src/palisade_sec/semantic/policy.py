"""POLICY: the editable, per-org conscience of the semantic layer.

The same TypeSafe judgment routes differently per company by adjusting
thresholds and criteria (see the guardrails cookbook). A fintech blocks at
harm >= 1; a hobby project at 3. Criteria are editable English that sharpens
the question sent to the model.

v1 ships defaults + programmatic overrides; file loading
(`.palisade/policy.yaml` / `[tool.palisade.semantic]`) is the next slice.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CheckPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Route above this probability -> block (in CI). Between review and action
    # thresholds -> review. Below review_threshold -> pass.
    action_threshold: float = 0.60
    review_threshold: float = 0.30
    # A tool counts as "gated" (mitigated) only if the confirmation probability
    # is at least this; below it, the action is treated as ungated.
    gate_threshold: float = 0.50
    # Harm (0-3) at or above this turns a review into a block.
    severity_block: int = 2
    # Editable English that sharpens the model's question.
    criteria: dict[str, str] = Field(default_factory=dict)


class SemanticPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checks: dict[str, CheckPolicy] = Field(default_factory=dict)

    def for_check(self, name: str) -> CheckPolicy:
        return self.checks.get(name, CheckPolicy())


def default_policy() -> SemanticPolicy:
    return SemanticPolicy(
        checks={
            "excessive_agency": CheckPolicy(
                criteria={
                    "irreversible": (
                        "deletes or overwrites data, spends money, sends "
                        "messages to customers, runs shell commands, or changes "
                        "production/cloud state"
                    ),
                },
            ),
        }
    )
