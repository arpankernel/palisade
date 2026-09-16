"""Phase-0 precision harness (roadmap: Measure).

Runs Palisade over a labeled corpus and computes precision / recall / F1,
failing (exit 1) when precision drops below the threshold. This is the CI
regression gate that protects every later change; the published number is a
byproduct.

Corpus manifest (YAML):

    threshold: 0.90
    targets:
      - path: examples/support-bot          # scanned relative to the manifest
        assume_params_untrusted: false
        expect:                              # ground truth
          - {file: app.py, line: 34, rule: PI-SQL,   verdict: flag}
          - {file: app.py, line: 49, rule: PI-SHELL, verdict: flag}
          - {file: app.py, line: 64, rule: PI-EXEC,  verdict: flag}
        # every finding NOT matching an `expect: flag` row counts as a
        # false positive; every `flag` row not found counts as a miss.

Usage: uv run python scripts/precision.py corpus/manifest.yaml
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from palisade_sec.scanner import run_scan  # noqa: E402


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def evaluate(manifest_path: Path) -> tuple[Metrics, list[str]]:
    doc = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    base = manifest_path.resolve().parent
    m = Metrics()
    detail: list[str] = []
    for target in doc.get("targets", []):
        root = (base / target["path"]).resolve()
        res = run_scan(root, assume_params_untrusted=target.get("assume_params_untrusted") or None)
        expected = {
            (e["file"], int(e["line"]), e["rule"])
            for e in target.get("expect", [])
            if e.get("verdict", "flag") == "flag"
        }
        got = {(f.sink.file, f.sink.line, f.rule_id) for f in res.findings}
        for hit in sorted(got & expected):
            m.tp += 1
            detail.append(f"TP {target['path']}: {hit}")
        for miss in sorted(expected - got):
            m.fn += 1
            detail.append(f"FN {target['path']}: expected {miss}, not found")
        for extra in sorted(got - expected):
            m.fp += 1
            detail.append(f"FP {target['path']}: unexpected {extra}")
    return m, detail


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    manifest = Path(sys.argv[1])
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    threshold = float(doc.get("threshold", 0.90))
    m, detail = evaluate(manifest)
    for line in detail:
        print(line)
    print(
        f"\nprecision={m.precision:.3f} recall={m.recall:.3f} f1={m.f1:.3f} "
        f"(tp={m.tp} fp={m.fp} fn={m.fn}; threshold={threshold})"
    )
    if m.precision < threshold:
        print("FAIL: precision below threshold")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
