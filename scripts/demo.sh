#!/usr/bin/env bash
#
# Palisade end-to-end demo on examples/support-bot.
#
# Runs the full path: scan (offline) -> map (offline) -> audit -> review, and
# writes the artifacts to ./palisade-demo/. The judgment steps (audit, review)
# read their endpoint and key from .env; nothing is hardcoded. If the key is
# not set, the demo stops with a clear message before any judgment call.
#
# Usage:
#   cp .env.example .env        # set PALISADE_JUDGE_* and your key
#   ./scripts/demo.sh           # or: OUT=/tmp/out ./scripts/demo.sh path/to/app
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$ROOT/examples/support-bot}"
OUT="${OUT:-$ROOT/palisade-demo}"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
PALISADE="${PALISADE:-palisade-sec}"

# Load .env if present (without clobbering values already in the environment
# is not possible with `.`, so an explicit .env wins; that is expected here).
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

BACKEND="${PALISADE_JUDGE_BACKEND:-typesafe}"
if [ "$BACKEND" = "typesafe" ]; then
  KEYVAR="TYPESAFE_API_KEY"
else
  KEYVAR="PALISADE_JUDGE_API_KEY"
fi
KEYVAL="${!KEYVAR:-}"

if [ -z "$KEYVAL" ]; then
  echo "error: $KEYVAR is not set." >&2
  echo "       Copy .env.example to .env and set it (or export it)." >&2
  echo "       The offline steps (scan, map) need no key; audit and review use" >&2
  echo "       the endpoint configured in .env." >&2
  exit 1
fi

mkdir -p "$OUT"
echo "target:  $TARGET"
echo "backend: $BACKEND"
echo "output:  $OUT"
echo

echo "== scan (offline, no key) =="
"$PALISADE" scan "$TARGET" --all
"$PALISADE" scan "$TARGET" --json >"$OUT/scan.json"

echo "== map (offline, no key) =="
"$PALISADE" map "$TARGET"
"$PALISADE" map "$TARGET" --json >"$OUT/map.json"

echo "== judgment layer (single pass over the $BACKEND endpoint) =="
# One judged pass produces the review report, its markdown, and the audit view.
# Running audit and review as separate passes would judge each finding twice and
# could disagree, because the model is probabilistic; composing from one pass
# keeps them consistent and halves the endpoint calls.
"$PALISADE" review "$TARGET" --json --report >"$OUT/review.json"
mv -f palisade-review.md "$OUT/review.md" 2>/dev/null || true

python3 - "$OUT/review.json" "$OUT/audit.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
# The audit findings came from the same judged pass; write them as an artifact.
json.dump(
    {"tool": "palisade-sec audit (from the review pass)",
     "checks_run": r.get("checks_run", []),
     "findings": r.get("audit_findings", [])},
    open(sys.argv[2], "w"), indent=2,
)
p = r["posture"]
print(f"posture {p['score']}/100 ({p['band']})  judged={p['judged']}  backend={p['backend']}")
print("breakdown:", r["breakdown"])
PY

echo
echo "artifacts written to $OUT: scan.json map.json audit.json review.json review.md"
