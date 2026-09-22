#!/usr/bin/env bash
# Smoke-test the CLI exactly as a user installs it: the built wheel, no
# extras, in a fresh venv. The test suite runs in the dev environment, which
# has every optional extra installed, so it cannot see what a plain
# `pip install palisade-sec` gets. 0.5.0 shipped two bugs that lived only
# there: `review`/`audit` crashed on a missing httpx, and a JS-only repo
# passed `scan --ci` with zero files scanned.
#
# Usage: scripts/smoke_install.sh path/to/palisade_sec-*.whl
set -uo pipefail

WHEEL="${1:?usage: smoke_install.sh <wheel>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Setup must succeed or nothing below means anything.
"${PYTHON:-python3}" -m venv "$WORK/venv" || { echo "FAIL  could not create venv"; exit 1; }
"$WORK/venv/bin/pip" install --quiet "$WHEEL" || { echo "FAIL  could not install $WHEEL"; exit 1; }
P="$WORK/venv/bin/palisade-sec"
APP="examples/vulnerable-app"
FAIL=0

# check <expected-exit> <description> -- <args...>
check() {
  local want="$1" desc="$2"; shift 3
  local out rc
  out="$("$P" "$@" 2>&1)"; rc=$?
  if [[ "$out" == *"Traceback"* ]]; then
    echo "FAIL  $desc: printed a Python traceback"; echo "$out" | tail -5; FAIL=1; return
  fi
  if [[ "$rc" != "$want" ]]; then
    echo "FAIL  $desc: exit $rc, expected $want"; echo "$out" | tail -5; FAIL=1; return
  fi
  echo "ok    $desc (exit $rc)"
}

# check_json <description> -- <args...>: stdout must be valid JSON
check_json() {
  local desc="$1"; shift 2
  if "$P" "$@" 2>/dev/null | "$WORK/venv/bin/python" -c "import json,sys; json.load(sys.stdin)"; then
    echo "ok    $desc (valid JSON)"
  else
    echo "FAIL  $desc: stdout is not valid JSON"; FAIL=1
  fi
}

mkdir -p "$WORK/empty" "$WORK/jsonly"
echo "notes" > "$WORK/empty/README.md"
printf 'const x = require("child_process");\n' > "$WORK/jsonly/server.js"

check 0 "--version"                      -- --version
check 1 "scan --ci blocks the example"   -- scan "$APP" --ci
check_json "scan --json"                 -- scan "$APP" --json
check_json "scan --sarif"                -- scan "$APP" --sarif
check 0 "map"                            -- map "$APP"
check 0 "fix"                            -- fix "$APP" --output "$WORK/fixes.md"
check 0 "redteam (synthesis)"            -- redteam "$APP"
check 0 "baseline"                       -- baseline "$APP" --output "$WORK/baseline.json"
check 0 "review without [judge]"         -- review "$APP"
check_json "review --json without [judge]" -- review "$APP" --json
check 2 "audit without [judge]"          -- audit "$APP"
check 2 "redteam --execute without [judge]" -- redteam "$APP" --execute --approve --target http://127.0.0.1:9
check 2 "scan --ci on an empty dir"      -- scan "$WORK/empty" --ci
check 2 "scan --ci on JS without [js]"   -- scan "$WORK/jsonly" --ci
check 2 "review --ci on an empty dir"    -- review "$WORK/empty" --ci
check 2 "missing explicit --config"      -- scan "$APP" --config "$WORK/nope.toml"
check 2 "redteam --variants out of range" -- redteam "$APP" --variants 99

exit "$FAIL"
