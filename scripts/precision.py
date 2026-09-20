"""Phase 0 precision harness (roadmap: Measure).

Scores Palisade against a labelled corpus and fails (exit 1) when precision
drops below the manifest threshold. The published number is a byproduct; the
CI regression gate is the point, because it is what stops a later change
silently degrading quality.

Two corpora, both real:

  fixtures  corpus/manifest.yaml - the project's own example apps, with
            exact expected findings. Fast, hermetic, runs on every push.
  repos     corpus/repos.yaml    - pinned third-party repos fetched by
            corpus/fetch.py. Slow, needs network, runs on a schedule.

Scoring:
  true positive   an expected finding that was reported
  false negative  an expected finding that was missed
  false positive  a reported finding that was not expected

For `clean` repos the expectation is "nothing", so every HIGH finding there
is a false positive until a human triages it and either fixes the rule or
records it as a genuine vulnerability via `expect`.

Usage:
    uv run python scripts/precision.py corpus/manifest.yaml
    uv run python scripts/precision.py corpus/repos.yaml --repos
    uv run python scripts/precision.py corpus/repos.yaml --repos --triage
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from palisade_sec.scanner import run_scan  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    detail: list[str] = field(default_factory=list)
    # Targets the engine scanned without minting a single untrusted source.
    # Their silence is unearned and must not be counted as precision.
    unchallenged: list[str] = field(default_factory=list)
    # Targets that DID mint at least one source. These are the ones the
    # precision claim actually rests on.
    challenged: int = 0
    # Targets that ASSERT they are challenged (library_mode, or kind: cve)
    # but minted nothing. Unlike plain unchallenged targets this is a real
    # defect - their ground-truth labels can never be reached - so it fails.
    misconfigured: list[str] = field(default_factory=list)

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


def _expected(target: dict) -> set[tuple[str, int, str]]:
    return {
        (e["file"], int(e["line"]), e["rule"])
        for e in target.get("expect", []) or []
        if e.get("verdict", "flag") == "flag"
    }


def score_fixtures(manifest: Path) -> tuple[Metrics, float]:
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    base = manifest.resolve().parent
    m = Metrics()
    for target in doc.get("targets", []):
        root = (base / target["path"]).resolve()
        res = run_scan(root, assume_params_untrusted=target.get("assume_params_untrusted") or None)
        # Same rule as the repo corpus: a fixture that mints no source cannot
        # produce a finding, so its silence proves nothing. These are the
        # project's own example apps with deliberate sources, so zero here is
        # always a defect (a broken frontend or a mislabelled target) rather
        # than the benign app-mode-library case, and it fails the run.
        if res.sources_found == 0:
            m.misconfigured.append(str(target["path"]))
        else:
            m.challenged += 1
        expected = _expected(target)
        got = {(f.sink.file, f.sink.line, f.rule_id) for f in res.findings}
        for hit in sorted(got & expected):
            m.tp += 1
            m.detail.append(f"TP  {target['path']}  {hit}")
        for miss in sorted(expected - got):
            m.fn += 1
            m.detail.append(f"FN  {target['path']}  expected {miss}, not found")
        for extra in sorted(got - expected):
            m.fp += 1
            m.detail.append(f"FP  {target['path']}  unexpected {extra}")
    return m, float(doc.get("threshold", 0.90))


def score_repos(manifest: Path, triage: bool) -> tuple[Metrics, float]:
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    dest = manifest.resolve().parent / "repos"
    m = Metrics()
    missing = []
    unchallenged = []
    for entry in doc.get("repos", []):
        root = dest / entry["name"]
        if not root.is_dir():
            missing.append(entry["name"])
            continue
        res = run_scan(root, assume_params_untrusted=entry.get("library_mode") or None)
        # A scan that minted no untrusted sources had nowhere for taint to
        # start, so "no findings" there is not evidence the code is clean -
        # it is an unchallenged scan being counted as a clean one. Silence
        # only means something when the engine had somewhere to begin.
        if res.sources_found == 0:
            # A target asserted to be challenged that mints nothing is a
            # genuine defect, not benign silence: `library_mode: true` says
            # "treat every public parameter as untrusted", and a `cve` target
            # is claimed to contain a reachable vulnerability. Either one
            # producing zero sources means the config or the frontend is
            # broken, and the recall label below would be unreachable.
            if entry.get("library_mode") or entry.get("kind") == "cve":
                print(
                    f"FAIL: {entry['name']} is declared "
                    f"{'library_mode' if entry.get('library_mode') else 'kind: cve'} "
                    "but minted no untrusted sources - its labels are unreachable.",
                    file=sys.stderr,
                )
                m.misconfigured.append(entry["name"])
            unchallenged.append(f"{entry['name']} ({res.files_scanned} files)")
        else:
            m.challenged += 1
        # Recall counts a finding at ANY severity: a real vulnerability that
        # Palisade deliberately downgrades to MED (a denylist or an unverified
        # sanitizer on the path) is still a hit, not a miss. Vanna's
        # CVE-2024-5565 is exactly this case.
        found = {(f.sink.file, f.sink.line, f.rule_id) for f in res.findings}
        # Precision counts only HIGH against us: advisory rules like PI-HTTP
        # are reported but never gate a user's CI, so they must not be scored
        # as false positives here either.
        high = {(f.sink.file, f.sink.line, f.rule_id) for f in res.findings if f.severity == "high"}
        expected = _expected(entry)
        got = found
        kind = entry.get("kind", "clean")
        for hit in sorted(got & expected):
            m.tp += 1
            m.detail.append(f"TP  {entry['name']:<16} {hit}")
        for miss in sorted(expected - got):
            m.fn += 1
            m.detail.append(f"FN  {entry['name']:<16} expected {miss}, not found")
        for extra in sorted(high - expected):
            m.fp += 1
            m.detail.append(f"FP  {entry['name']:<16} ({kind}) unexpected {extra}")
            if triage:
                f = next(x for x in res.findings if (x.sink.file, x.sink.line, x.rule_id) == extra)
                m.detail.append(
                    f"      source: {f.source.snippet}  ({f.source.file}:{f.source.line})"
                )
                m.detail.append(f"      llm   : {f.llm.snippet}  ({f.llm.file}:{f.llm.line})")
                m.detail.append(f"      sink  : {f.sink.snippet}")
    if missing:
        print(f"not fetched ({len(missing)}): {', '.join(missing)}", file=sys.stderr)
        print("run: uv run python corpus/fetch.py", file=sys.stderr)
    if unchallenged:
        m.unchallenged = unchallenged
    return m, float(doc.get("threshold", 0.90))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--repos", action="store_true", help="score the pinned third-party corpus")
    ap.add_argument("--triage", action="store_true", help="print the trace for each false positive")
    args = ap.parse_args()

    m, threshold = (
        score_repos(args.manifest, args.triage) if args.repos else score_fixtures(args.manifest)
    )
    for line in m.detail:
        print(line)

    # A run that measured nothing must never report success. precision is
    # defined as 1.0 when tp+fp is 0, so an unlabelled corpus otherwise
    # sails through the gate and manufactures false confidence - which is
    # exactly the failure this harness exists to prevent.
    if m.tp + m.fn == 0:
        print(
            "\nFAIL: no expected findings were scored. The corpus has no "
            "ground-truth `expect:` entries, so recall is unmeasurable and "
            "this run proves nothing."
        )
        return 1

    # The precision-side twin of the check above. Recall goes vacuous when
    # nothing is labelled; precision goes vacuous when nothing is *challenged*.
    # A target that mints no untrusted source cannot produce a finding at all,
    # so its silence is not evidence of precision.
    #
    # But an unchallenged target is not a *failure*. A library scanned in app
    # mode legitimately has no `request.*`, no `input()`, no `sys.argv` - that
    # is correct behaviour, and failing the build on it would turn the gate
    # red for code that is working exactly as designed. `llm-cli` and
    # `outlines` are both this case today.
    #
    # So: exclude them from the claim and say so, rather than failing. The
    # gate fails only when a target that was *supposed* to be challenged was
    # not (see score_repos), or when nothing was challenged at all.
    if m.unchallenged:
        print(
            f"\nnote: {len(m.unchallenged)} target(s) minted no untrusted "
            "sources. Taint had nowhere to start, so their silence is not "
            "evidence of precision and they are excluded from the claim:"
        )
        for name in m.unchallenged:
            print(f"  unchallenged  {name}")
    # Checked BEFORE the wholly-vacuous case below. A corpus whose only
    # target is a misconfigured one satisfies both conditions, and "your cve
    # target mints nothing" names the actual defect, where "nothing was
    # challenged" only describes the symptom and sends the reader hunting.
    if m.misconfigured:
        print(
            f"\nFAIL: {len(m.misconfigured)} target(s) declare themselves "
            "challenged (library_mode, or kind: cve) but minted no untrusted "
            "sources, so their ground-truth labels are unreachable: " + ", ".join(m.misconfigured)
        )
        return 1
    if m.challenged == 0:
        print(
            "\nFAIL: no target minted a single untrusted source, so nothing "
            "was challenged and this run proves nothing about precision."
        )
        return 1
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
