"""`review` composition + posture. Unit tests pin the posture guardrails; the
integration tests run on the support-bot fixture, taint-only and judged, with a
FakeBackend (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from palisade_sec.judge.base import FakeBackend
from palisade_sec.judge.types import NoulAns, ScoreAns
from palisade_sec.semantic.review import ReviewReport, RiskItem, run_review

SUPPORT_BOT = Path(__file__).resolve().parent.parent / "examples" / "support-bot"


def _report(items: list[RiskItem], judged=False, verified=True) -> ReviewReport:
    return ReviewReport(
        items=items,
        taint_findings=[],
        ai_surface={"llm_calls": 0, "prompts": 0, "tools": 0, "agents": 0},
        attacks_synthesized=0,
        files_scanned=1,
        judged=judged,
        backend_name="fake" if judged else None,
        backend_verified=verified,
    )


def _item(risk_l, risk_i, verified, kind="taint") -> RiskItem:
    return RiskItem(
        kind=kind,
        title="x",
        file="a.py",
        line=1,
        likelihood=risk_l,
        impact=risk_i,
        verified=verified,
        judged=False,
    )


# -- posture guardrails -----------------------------------------------------


def test_verified_high_risk_yields_critical_band():
    report = _report([_item(0.9, 1.0, verified=True)])
    score, band = report.posture()
    assert band == "Critical"
    assert score < 60


def test_unverified_cannot_manufacture_critical():
    # An unverified excessive-agency item at high judged risk: tier capped to
    # high, and the band cannot reach Critical without a verified high signal.
    report = _report(
        [_item(0.95, 1.0, verified=False, kind="excessive_agency")], judged=True, verified=False
    )
    assert report.items[0].tier == "high"  # capped, never critical
    _, band = report.posture()
    assert band != "Critical"


def test_clean_project_is_full_posture():
    report = _report([])
    score, band = report.posture()
    assert score == 100
    assert band == "Low"


def test_breakdown_is_shown_with_score():
    d = _report([_item(0.9, 1.0, verified=True)]).to_dict()
    assert d["posture"]["over"].startswith("detected findings")
    assert set(d["breakdown"]) == {"critical", "high", "moderate", "low"}


# -- integration on support-bot --------------------------------------------


def test_review_taint_only_labels_and_scores():
    report = run_review(SUPPORT_BOT, backend=None)
    assert report.judged is False
    assert report.items  # support-bot has real taint findings
    assert all(i.kind == "taint" and not i.judged for i in report.items)
    _, band = report.posture()
    assert band == "Critical"  # deliberately vulnerable app, HIGH findings
    d = report.to_dict()
    assert d["posture"]["judged"] is False


def test_review_judged_with_fake_backend():
    backend = FakeBackend(
        answers={
            "exploitable": NoulAns(0.9),
            "severity": ScoreAns(3.0),
            "irreversible": NoulAns(0.9),
            "gated": NoulAns(0.0),
            "harm": ScoreAns(3.0),
        }
    )
    report = run_review(SUPPORT_BOT, backend=backend)
    assert report.judged is True
    assert report.backend_verified is True
    assert any(i.judged for i in report.items)  # exploitability refined the taint items


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
