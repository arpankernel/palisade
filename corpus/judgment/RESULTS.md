# Judgment-layer calibration — measured results

Point-in-time, from `scripts/calibrate.py corpus/judgment/cases.yaml`. The
judgment layer is probabilistic, so numbers vary run-to-run; these are a
snapshot, like the deterministic corpus precision.

- **Date:** 2026-09-21
- **Backend:** TypeSafe (`jev-latest`), verified/calibrated
- **Corpus:** 10 labelled cases (taint-exploitability + excessive-agency)

## Yes/no (Noul) signals

| Signal | n | Precision | Recall | Accuracy | Brier |
|---|---|---|---|---|---|
| `exploitable` | 4 | 1.00 | 1.00 | 1.00 | 0.023 |
| `irreversible` | 6 | 1.00 | 1.00 | 1.00 | 0.002 |
| `gated` | 6 | **0.67** | 1.00 | 0.83 | 0.085 |

## Ordinal (Score) signals — tier 0–3

| Signal | n | Exact | Within-1 | MAE |
|---|---|---|---|---|
| `severity` | 4 | 0.50 | **1.00** | 0.48 |
| `harm` | 6 | 0.50 | **1.00** | 0.37 |

## Verdict

**Calibrated (clears the gate):** `exploitable`, `irreversible` (precision/recall
1.00, low Brier), and `severity`/`harm` within +/-1 tier (exact-match is too
strict for an ordinal scale; MAE < 0.5).

**Known-weak (measured, excluded from the hard gate, not silenced):** `gated`.
The model over-predicts gating (precision 0.67) on this seed. Because a false
"gated" would *downgrade* a genuinely dangerous tool, this signal is not trusted
to suppress a finding until the corpus and the state passed to the model are
rich enough to judge it reliably. Tracked in `corpus/judgment/cases.yaml`
(`known_weak: [gated]`).
