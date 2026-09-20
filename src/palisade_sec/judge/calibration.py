"""Calibration harness for the judgment layer.

The deterministic detections (taint rules, PI-AGENT-HANDOFF) carry a measured,
CI-gated precision. The *judged* signals - exploitability, excessive agency -
do not, and are labelled "uncalibrated" everywhere until they are scored here.

This measures how well a JudgeBackend agrees with ground-truth labels on a
corpus of grounded cases: for each yes/no (Noul) question, precision / recall /
accuracy plus a Brier score (is a stated 0.8 really ~80% right?); for each Score
question, exact-tier accuracy and mean absolute error. The scoring is pure and
tested offline with a fake backend; a real run needs a configured endpoint and
produces the published numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from palisade_sec.judge.base import JudgeBackend, JudgeError
from palisade_sec.judge.types import NoulQ, ScoreQ
from palisade_sec.semantic.exploitability import exploitability_questions
from palisade_sec.semantic.judge import excessive_agency_questions
from palisade_sec.semantic.policy import default_policy

# Which questions each check asks (so a label maps to the right answer).
QUESTIONS_FOR_CHECK = {
    "excessive_agency": lambda: excessive_agency_questions(
        default_policy().for_check("excessive_agency")
    ),
    "taint_exploitability": lambda: exploitability_questions(),
}


@dataclass
class CalibrationCase:
    id: str
    check: str
    state: dict
    labels: dict  # qid -> bool (Noul) or int (Score)


@dataclass
class NoulMetric:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    brier_sum: float = 0.0
    n: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 1.0

    @property
    def brier(self) -> float:
        return self.brier_sum / self.n if self.n else 0.0

    def to_dict(self) -> dict:
        return {
            "kind": "noul",
            "n": self.n,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "accuracy": round(self.accuracy, 3),
            "brier": round(self.brier, 3),
        }


@dataclass
class ScoreMetric:
    n: int = 0
    exact: int = 0
    abs_err_sum: float = 0.0

    @property
    def accuracy(self) -> float:
        return self.exact / self.n if self.n else 1.0

    @property
    def mae(self) -> float:
        return self.abs_err_sum / self.n if self.n else 0.0

    def to_dict(self) -> dict:
        return {
            "kind": "score",
            "n": self.n,
            "accuracy": round(self.accuracy, 3),
            "mae": round(self.mae, 3),
        }


@dataclass
class CalibrationReport:
    noul: dict[str, NoulMetric] = field(default_factory=dict)
    score: dict[str, ScoreMetric] = field(default_factory=dict)
    backend: str = ""
    verified: bool = True
    cases: int = 0
    errors: list[str] = field(default_factory=list)

    def passed(self, noul_precision_min: float, score_accuracy_min: float) -> bool:
        if self.errors:
            return False
        ok = all(m.precision >= noul_precision_min for m in self.noul.values())
        ok = ok and all(m.accuracy >= score_accuracy_min for m in self.score.values())
        return ok

    def to_dict(self) -> dict:
        return {
            "tool": "palisade-sec calibrate",
            "backend": self.backend,
            "verified": self.verified,
            "cases": self.cases,
            "noul": {q: m.to_dict() for q, m in self.noul.items()},
            "score": {q: m.to_dict() for q, m in self.score.items()},
            "errors": self.errors,
        }


def _kind_map(check: str) -> dict[str, str]:
    kinds: dict[str, str] = {}
    for q in QUESTIONS_FOR_CHECK[check]():
        if isinstance(q, NoulQ):
            kinds[q.id] = "noul"
        elif isinstance(q, ScoreQ):
            kinds[q.id] = "score"
    return kinds


def load_cases(path: Path) -> tuple[list[CalibrationCase], dict]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cases = [
        CalibrationCase(id=c["id"], check=c["check"], state=c["state"], labels=c["labels"])
        for c in doc.get("cases", [])
    ]
    return cases, doc.get("threshold", {})


def evaluate(
    cases: list[CalibrationCase], backend: JudgeBackend, threshold: float = 0.5
) -> CalibrationReport:
    report = CalibrationReport(backend=backend.name, verified=backend.verified, cases=len(cases))
    for case in cases:
        kinds = _kind_map(case.check)
        try:
            result = backend.ask(case.state, list(QUESTIONS_FOR_CHECK[case.check]()))
        except JudgeError as exc:
            report.errors.append(f"{case.id}: {exc}")
            continue
        for qid, label in case.labels.items():
            kind = kinds.get(qid)
            try:
                if kind == "noul":
                    _score_noul(
                        report.noul.setdefault(qid, NoulMetric()),
                        result.noul(qid),
                        bool(label),
                        threshold,
                    )
                elif kind == "score":
                    _score_score(
                        report.score.setdefault(qid, ScoreMetric()), result.score(qid), int(label)
                    )
            except JudgeError as exc:
                report.errors.append(f"{case.id}/{qid}: {exc}")
    return report


def _score_noul(m: NoulMetric, prob: float, label: bool, threshold: float) -> None:
    predicted = prob >= threshold
    m.n += 1
    m.brier_sum += (prob - (1.0 if label else 0.0)) ** 2
    if predicted and label:
        m.tp += 1
    elif predicted and not label:
        m.fp += 1
    elif not predicted and label:
        m.fn += 1
    else:
        m.tn += 1


def _score_score(m: ScoreMetric, value: float, label: int) -> None:
    m.n += 1
    if round(value) == label:
        m.exact += 1
    m.abs_err_sum += abs(value - label)
