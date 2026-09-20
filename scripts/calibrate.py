"""Calibrate the judgment layer against the labelled corpus.

Runs the configured JudgeBackend (from .env) over corpus/judgment/cases.yaml and
reports per-question precision / recall / accuracy / Brier (Noul) and exact-tier
accuracy / MAE (Score). Exits non-zero if a signal is below the corpus
thresholds, so judged quality can only ratchet up - the same discipline as the
deterministic precision gate.

    uv run python scripts/calibrate.py corpus/judgment/cases.yaml

Needs an endpoint + key configured in .env (see .env.example). The offline core
and the deterministic precision gate do not depend on this.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from palisade_sec.judge.base import JudgeError  # noqa: E402
from palisade_sec.judge.calibration import evaluate, load_cases  # noqa: E402
from palisade_sec.judge.config import describe, get_backend  # noqa: E402


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("corpus/judgment/cases.yaml")
    cases, threshold = load_cases(path)
    if not cases:
        print(f"no calibration cases in {path}", file=sys.stderr)
        return 2
    try:
        backend = get_backend()
    except JudgeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"calibrating {len(cases)} case(s) against {describe(backend)}\n")
    report = evaluate(cases, backend)
    print(json.dumps(report.to_dict(), indent=2))

    noul_min = float(threshold.get("noul_precision", 0.80))
    score_min = float(threshold.get("score_accuracy", 0.60))
    if not backend.verified:
        print(
            "\nnote: backend is unverified (best-effort); these numbers do not "
            "certify the signal, they profile this backend.",
            file=sys.stderr,
        )
    if report.passed(noul_min, score_min):
        print(f"\nOK - calibrated (noul precision >= {noul_min}, score accuracy >= {score_min})")
        return 0
    print(
        f"\nFAIL - below threshold (noul precision {noul_min}, score accuracy {score_min})",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
