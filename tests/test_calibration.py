"""Calibration harness metrics, exercised offline with a scripted backend. No
network. Also checks the seed corpus loads and is well-formed."""

from __future__ import annotations

from pathlib import Path

from palisade_sec.judge.base import JudgeError
from palisade_sec.judge.calibration import (
    CalibrationCase,
    evaluate,
    load_cases,
)
from palisade_sec.judge.types import JudgeResult, NoulAns, ScoreAns

ROOT = Path(__file__).resolve().parent.parent


class ScriptedBackend:
    """Returns answers from hints embedded in the case state (`_expl`, `_sev`,
    `_irr`, `_gated`, `_harm`), so a test can drive per-case behavior."""

    name = "scripted"
    verified = True

    def ask(self, state, questions) -> JudgeResult:
        m = {
            "exploitable": ("_expl", NoulAns),
            "irreversible": ("_irr", NoulAns),
            "gated": ("_gated", NoulAns),
            "severity": ("_sev", ScoreAns),
            "harm": ("_harm", ScoreAns),
        }
        answers = {}
        for q in questions:
            if q.id in m:
                key, cls = m[q.id]
                answers[q.id] = cls(float(state.get(key, 0.0)))
        return JudgeResult(answers=answers, backend=self.name, verified=True)


class RaisingBackend:
    name = "raising"
    verified = True

    def ask(self, state, questions) -> JudgeResult:
        raise JudgeError("endpoint unreachable")


def _expl(id_, p, sev, label_exp, label_sev):
    return CalibrationCase(
        id=id_,
        check="taint_exploitability",
        state={"_expl": p, "_sev": sev},
        labels={"exploitable": label_exp, "severity": label_sev},
    )


def test_perfect_backend_scores_perfectly():
    cases = [_expl("a", 0.9, 3, True, 3), _expl("b", 0.05, 0, False, 0)]
    r = evaluate(cases, ScriptedBackend())
    assert r.noul["exploitable"].precision == 1.0
    assert r.noul["exploitable"].recall == 1.0
    assert r.noul["exploitable"].accuracy == 1.0
    assert r.noul["exploitable"].brier < 0.02
    assert r.score["severity"].accuracy == 1.0
    assert r.score["severity"].mae == 0.0
    assert r.passed(0.8, 0.6)


def test_false_negative_lowers_recall_not_precision():
    cases = [_expl("miss", 0.2, 3, True, 3), _expl("tn", 0.1, 0, False, 0)]
    r = evaluate(cases, ScriptedBackend())
    m = r.noul["exploitable"]
    assert m.recall == 0.0  # the one positive was missed
    # No positive prediction was made, so precision is UNDEFINED - not a vacuous
    # 1.0. A signal that misses every positive must not clear the gate.
    assert not m.precision_defined
    assert not r.passed(0.8, 0.6)


def test_unexercised_signal_does_not_pass_the_gate():
    """A signal with no positive labels used to read precision 1.0 and clear the
    gate. It is now reported as unexercised and fails unless marked known_weak."""
    cases = [_expl("neg1", 0.05, 0, False, 0), _expl("neg2", 0.1, 0, False, 0)]
    r = evaluate(cases, ScriptedBackend())
    m = r.noul["exploitable"]
    assert not m.has_positive_labels
    assert m.to_dict()["precision"] is None  # not a vacuous 1.0
    assert "exploitable" in r.unexercised_signals()
    assert "exploitable" in r.weak_signals(0.8, 0.6)
    assert not r.passed(0.8, 0.6)
    assert r.passed(0.8, 0.6, known_weak=("exploitable",))


def test_false_positive_fails_the_gate():
    cases = [_expl("fp", 0.9, 0, False, 0), _expl("tp", 0.9, 3, True, 3)]
    r = evaluate(cases, ScriptedBackend())
    assert r.noul["exploitable"].precision == 0.5  # 1 tp, 1 fp
    assert not r.passed(0.8, 0.6)


def test_known_weak_signal_is_excluded_from_gate_but_still_reported():
    # `exploitable` is weak here, but marking it known-weak lets the gate pass
    # while weak_signals still surfaces it.
    cases = [_expl("fp", 0.9, 3, False, 3), _expl("tp", 0.9, 3, True, 3)]
    r = evaluate(cases, ScriptedBackend())
    assert "exploitable" in r.weak_signals(0.8, 0.8)
    assert not r.passed(0.8, 0.8)  # weak by default
    assert r.passed(0.8, 0.8, known_weak=("exploitable",))  # excluded, gate passes


def test_backend_error_is_captured_and_fails_gate():
    r = evaluate([_expl("x", 0.9, 3, True, 3)], RaisingBackend())
    assert r.errors
    assert not r.passed(0.8, 0.6)


def test_excessive_agency_case_scores_all_questions():
    case = CalibrationCase(
        id="del",
        check="excessive_agency",
        state={"_irr": 0.95, "_gated": 0.02, "_harm": 3},
        labels={"irreversible": True, "gated": False, "harm": 3},
    )
    r = evaluate([case], ScriptedBackend())
    assert r.noul["irreversible"].tp == 1
    assert r.noul["gated"].tn == 1
    assert r.score["harm"].exact == 1


def test_seed_corpus_loads_and_is_wellformed():
    cases, threshold = load_cases(ROOT / "corpus" / "judgment" / "cases.yaml")
    assert len(cases) >= 6
    assert threshold["noul_precision"] > 0
    checks = {c.check for c in cases}
    assert checks == {"taint_exploitability", "excessive_agency"}
    # every labelled qid must be a real question of its check
    from palisade_sec.judge.calibration import _kind_map

    for c in cases:
        kinds = _kind_map(c.check)
        for qid in c.labels:
            assert qid in kinds, f"{c.id}: unknown question {qid}"
