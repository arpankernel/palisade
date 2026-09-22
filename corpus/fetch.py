"""Fetch the benchmark corpus at its pinned commits.

Every repo in repos.yaml is checked out into corpus/repos/<name> at exactly
the commit recorded in corpus/repos.lock.json. That is what makes the corpus
"pinned": before 0.5.2 the lock was written but never read, so every run
re-cloned the latest default branch of the 23 clean repos, and ground-truth
labels (file:line) in them would have drifted within a week.

Usage:
    uv run python corpus/fetch.py            # check out the locked commits
    uv run python corpus/fetch.py --force    # re-fetch everything, still locked
    uv run python corpus/fetch.py --update   # move to the latest ref/default
                                             # branch and rewrite the lock
                                             # (re-verify labels afterwards)
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


def _git(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True, timeout=timeout)


def clone(entry: dict, force: bool, pinned: str | None) -> tuple[str, str | None, str]:
    """Check out `entry` at the `pinned` commit, or resolve its ref / default
    branch when there is no pin (a new repo, or --update)."""
    name = entry["name"]
    target = DEST / name
    if target.exists():
        current = head_sha(target)
        if not force and (pinned is None or current == pinned):
            return name, current, "cached"
        shutil.rmtree(target)
    try:
        if pinned:
            # Fetch exactly the locked commit (GitHub serves any reachable SHA).
            target.mkdir(parents=True)
            for step in (
                ("-C", str(target), "init", "--quiet"),
                ("-C", str(target), "remote", "add", "origin", entry["url"]),
                ("-C", str(target), "fetch", "--quiet", "--depth", "1", "origin", pinned),
                ("-C", str(target), "checkout", "--quiet", "FETCH_HEAD"),
            ):
                r = _git(*step)
                if r.returncode != 0:
                    break
        else:
            cmd = ["clone", "--quiet", "--depth", "1", "--single-branch"]
            if entry.get("ref"):
                cmd += ["--branch", str(entry["ref"])]
            r = _git(*cmd, entry["url"], str(target))
    except subprocess.TimeoutExpired:
        # One slow clone must never hang the whole corpus run.
        shutil.rmtree(target, ignore_errors=True)
        return name, None, "TIMEOUT"
    if r.returncode != 0:
        # A pin or tag that cannot be fetched must be visible, never silently
        # swapped for another commit, or the ground truth drifts.
        shutil.rmtree(target, ignore_errors=True)
        tail = (r.stderr or "").strip().splitlines()
        return name, None, "FAILED: " + (tail[-1] if tail else "?")
    got = head_sha(target)
    if pinned and got != pinned:
        shutil.rmtree(target, ignore_errors=True)
        return name, None, f"FAILED: got {got}, expected pinned {pinned}"
    return name, got, "fetched" if pinned else "cloned"


def head_sha(path: Path) -> str | None:
    r = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return r.stdout.strip() or None


def main() -> int:
    force = "--force" in sys.argv
    update = "--update" in sys.argv
    doc = yaml.safe_load((ROOT / "repos.yaml").read_text(encoding="utf-8"))
    entries = doc["repos"]
    DEST.mkdir(exist_ok=True)
    (DEST / ".gitignore").write_text("*\n", encoding="utf-8")

    locked: dict[str, dict] = {}
    if LOCK.is_file() and not update:
        locked = json.loads(LOCK.read_text(encoding="utf-8"))

    lock: dict[str, dict] = {}
    failed = []

    def pin_for(e: dict) -> str | None:
        rec = locked.get(e["name"])
        # A changed url or ref in repos.yaml invalidates the old pin.
        if rec and rec.get("url") == e["url"] and rec.get("ref") == e.get("ref"):
            return rec.get("sha")
        return None

    def safe_clone(e):
        try:
            return clone(e, force or update, pin_for(e))
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

    if failed:
        # Keep the old pins for anything that failed rather than dropping them.
        for name in failed:
            if name in locked:
                lock[name] = locked[name]
    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\n{len(lock)} repos pinned -> {LOCK.name}")
    if failed:
        # Scoring a partial corpus would quietly change what the precision
        # and recall numbers mean, so a failed fetch fails the run.
        print("failed:", ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
