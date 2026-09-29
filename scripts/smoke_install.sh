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
# A plain install must behave the same for everyone: no keychain, no
# inherited credentials, no logged-in gh CLI leaking into the checks.
export XDG_CONFIG_HOME="$WORK/config" PALISADE_NO_KEYRING=1
unset GITHUB_TOKEN GH_TOKEN PALISADE_GITHUB_TOKEN PALISADE_SLACK_WEBHOOK
# Empty, not unset: with a client id present, `connect github` would start
# the device flow and block forever waiting for a browser.
export PALISADE_GITHUB_CLIENT_ID=""
export PATH="$WORK/nogh:$PATH"; mkdir -p "$WORK/nogh"
printf '#!/bin/sh\nexit 1\n' > "$WORK/nogh/gh"; chmod +x "$WORK/nogh/gh"
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

# check_says <expected-exit> <description> <substring> -- <args...>: the exit
# code AND the sentence. Several bugs exited correctly while printing a
# message that sent the user nowhere.
check_says() {
  local want="$1" desc="$2" needle="$3"; shift 4
  local out rc
  out="$("$P" "$@" 2>&1)"; rc=$?
  # Rich hard-wraps at the terminal width, so compare against one long line.
  local flat; flat="$(echo "$out" | tr -d '\n')"
  if [[ "$rc" != "$want" ]]; then
    echo "FAIL  $desc: exit $rc, expected $want"; echo "$out" | tail -5; FAIL=1; return
  fi
  if [[ "$flat" != *"$needle"* ]]; then
    echo "FAIL  $desc: output did not mention '$needle'"; echo "$out" | tail -5; FAIL=1; return
  fi
  echo "ok    $desc (exit $rc, says so)"
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
check 0 "connections (nothing connected)" -- connections
check 2 "notify without a channel"       -- notify "$APP"
check 2 "pr without a token"             -- pr "$APP" --repo owner/name
check 0 "notify --slack --dry-run"       -- notify "$APP" --slack --dry-run

# A surface refusing to connect is the user's situation, not a crash. Each of
# these reached the exit-3 "this is a bug in palisade-sec, please report it"
# handler before 0.6.0 - including the one a first-time user hits first.
check_says 2 "connect github with no gh and no OAuth app" \
  "gh auth login"                        -- connect github --no-gh
check_says 2 "connect slack with a mistyped webhook" \
  "hooks.slack.com"                      -- connect slack --webhook "https://example.com/nope" --no-test
check_says 2 "connect llm rejects an unknown provider" \
  "must be one of"                       -- connect llm --provider gemini --key x --no-verify
check_says 2 "disconnect rejects an unknown surface" \
  "github, slack, llm"                   -- disconnect nonsense

# An install hint must survive being printed: rich reads the `[js]` in
# `pip install 'palisade-sec[js]'` as a style tag and deletes it, leaving a
# command that succeeds and installs nothing.
check_says 0 "scan names the js extra" \
  "palisade-sec[js]"                     -- scan "$WORK/jsonly"
check_says 0 "baseline names the js extra" \
  "palisade-sec[js]"                     -- baseline "$WORK/jsonly" --output "$WORK/js-baseline.json"

# A dry run is a pre-flight; it must not report success for a real run that
# cannot start for want of a credential.
check_says 2 "pr --dry-run without a token" \
  "NOT CONNECTED"                        -- pr "$APP" --repo owner/name --dry-run

exit "$FAIL"
