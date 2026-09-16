"""Fetch the Phase 0 benchmark corpus as pinned shallow clones.

Clones every repo in repos.yaml into corpus/repos/<name> and records the
resolved commit SHA in corpus/repos.lock.json, so a scored run is
reproducible even for entries that track a default branch.

Usage:
    uv run python corpus/fetch.py            # fetch anything missing
    uv run python corpus/fetch.py --force    # re-clone everything
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
DEST = ROOT / "repos"
LOCK = ROOT / "repos.lock.json"


def clone(entry: dict, force: bool) -> tuple[str, str | None, str]:
    name = entry["name"]
    target = DEST / name
    if target.exists():
        if not force:
            return name, head_sha(target), "cached"
        shutil.rmtree(target)
    cmd = ["git", "clone", "--quiet", "--depth", "1", "--single-branch"]
    if entry.get("ref"):
        cmd += ["--branch", str(entry["ref"])]
    cmd += [entry["url"], str(target)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        # One slow clone must never abort the whole corpus run.
        shutil.rmtree(target, ignore_errors=True)
        return name, None, "TIMEOUT"
    if r.returncode != 0:
        # A pinned tag that does not exist must be visible, not silently
        # swapped for the default branch, or the ground truth drifts.
        shutil.rmtree(target, ignore_errors=True)
        tail = (r.stderr or "").strip().splitlines()
        return name, None, "FAILED: " + (tail[-1] if tail else "?")
    return name, head_sha(target), "cloned"


def head_sha(path: Path) -> str | None:
    r = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return r.stdout.strip() or None


def main() -> int:
    force = "--force" in sys.argv
    doc = yaml.safe_load((ROOT / "repos.yaml").read_text(encoding="utf-8"))
    entries = doc["repos"]
    DEST.mkdir(exist_ok=True)
    (DEST / ".gitignore").write_text("*\n", encoding="utf-8")

    lock: dict[str, dict] = {}
    failed = []

    def safe_clone(e):
        try:
            return clone(e, force)
        except Exception as exc:  # noqa: BLE001 - a corpus fetch must never crash
            return e["name"], None, f"ERROR: {type(exc).__name__}"

    with ThreadPoolExecutor(max_workers=6) as pool:
        for name, sha, status in pool.map(safe_clone, entries):
            entry = next(e for e in entries if e["name"] == name)
            print(f"{status:<8} {name:<18} {sha[:12] if sha else '-'}")
            if sha:
                lock[name] = {"url": entry["url"], "ref": entry.get("ref"), "sha": sha}
            else:
                failed.append(name)

    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\n{len(lock)} repos pinned -> {LOCK.name}")
    if failed:
        print("failed:", ", ".join(failed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
