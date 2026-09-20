"""Shared risk model for the composed `review`.

risk = likelihood x impact, both normalized to 0..1. Tiers and the posture
score are derived from that, never asserted. The posture score is a function of
the tiers beneath it (see posture_score); the report always prints the
breakdown next to it so the number is never separable from what produced it.

Honesty rules encoded here:
- A finding whose risk rests on an UNVERIFIED (generic-backend) judgment can
  never reach the `critical` tier: `tier_of(risk, verified=False)` caps at high.
- The posture band can only reach `Critical` when a VERIFIED signal is high or
  critical; `critical_band_allowed` enforces that so an unverified backend
  cannot manufacture a Critical posture on judgment alone.
"""

from __future__ import annotations

# Likelihood from deterministic taint confidence (used when no judgment refines).
CONF_LIKELIHOOD = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.35}
# Impact from the rule severity (0..1).
SEV_IMPACT = {"high": 1.0, "med": 0.6, "low": 0.3}

TIERS = ("critical", "high", "moderate", "low")


def static_likelihood(confidence: str, risky: bool) -> float:
    base = CONF_LIKELIHOOD.get(confidence, 0.35)
    # A partial defense (denylist / confirmation gate) lowers likelihood but
    # never to zero - those were bypassed in real CVEs.
    return round(base * 0.7, 3) if risky else base


def static_impact(severity: str) -> float:
    return SEV_IMPACT.get(severity, 0.3)


def tier_of(risk: float, verified: bool = True) -> str:
    if risk >= 0.60:
        tier = "critical"
    elif risk >= 0.35:
        tier = "high"
    elif risk >= 0.15:
        tier = "moderate"
    else:
        tier = "low"
    if tier == "critical" and not verified:
        return "high"  # unverified judgment cannot reach critical
    return tier


def posture_score(counts: dict[str, int]) -> int:
    """0..100, derived from the tier counts. Higher is a better posture. The
    penalty is capped so the score floors at 0 rather than going negative."""
    penalty = (
        45 * counts.get("critical", 0)
        + 20 * counts.get("high", 0)
        + 7 * counts.get("moderate", 0)
        + 1.5 * counts.get("low", 0)
    )
    return max(0, round(100 - min(100.0, penalty)))


def posture_band(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 60:
        return "Moderate"
    if score >= 35:
        return "High"
    return "Critical"


def critical_band_allowed(items_verified_tiers: list[tuple[bool, str]]) -> bool:
    """A Critical posture requires at least one verified high/critical signal."""
    return any(verified and tier in ("critical", "high") for verified, tier in items_verified_tiers)


# Bands run Low < Moderate < High < Critical. The posture band is the MORE
# severe of the score-derived band and the worst individual tier present, so a
# single critical finding is never diluted into a milder headline.
_BAND_ORDER = ("Low", "Moderate", "High", "Critical")
_TIER_TO_BAND = {"critical": "Critical", "high": "High", "moderate": "Moderate", "low": "Low"}


def more_severe_band(a: str, b: str) -> str:
    return a if _BAND_ORDER.index(a) >= _BAND_ORDER.index(b) else b


def worst_band(tiers: list[str]) -> str:
    band = "Low"
    for t in tiers:
        band = more_severe_band(band, _TIER_TO_BAND.get(t, "Low"))
    return band
