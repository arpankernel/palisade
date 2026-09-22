---
title: "CLI reference"
description: "Every command, flag, exit code, config key, and the stable JSON schema."
---

```
palisade-sec [--version] <command> [args]
```

Commands split into two layers. The **offline core** makes no network calls,
needs no API key, and sends no telemetry. The **judgment layer** calls an
endpoint you configure in `.env` - TypeSafe by default, or any OpenAI-compatible
endpoint. Everything is MIT and free to run; the split is keyless-and-offline
versus bring-your-own-endpoint. Full setup in the
[judgment layer guide](judgment-layer.md).

| Command | Needs a judgment endpoint? |
|---|---|
| `scan`, `map`, `baseline`, `fix`, `redteam` (synthesis) | **No** - offline, keyless |
| `audit` | **Yes** |
| `review` | Only for the AI-judged layer; runs **taint-only** without a key |
| `redteam --execute` | **Yes** |

## Exit codes (the contract)

| Code | Meaning |
|---|---|
| `0` | Success. Includes "findings exist but `--ci` not set" and "all findings baselined under `--ci`". |
| `1` | `--ci` was set and at least one **new HIGH** finding exists. |
| `2` | Usage error (e.g. target path does not exist). |

## `palisade-sec scan [PATH]`

Scan a file or directory (default `.`) for source → LLM → sink paths.

| Flag | Effect |
|---|---|
| `--all` | Show MED/LOW findings too. Default view: HIGH + "risky" downgraded findings. |
| `--json` | Emit the stable JSON document (below) to stdout instead of terminal output. |
| `--sarif` | Emit SARIF 2.1.0 to stdout, for GitHub code scanning / any AppSec pipeline. |
| `--report` | Also write `palisade-report.md` - a shareable mini threat model grouped by severity. |
| `--ci` | Exit `1` if any (new, when combined with `--baseline`) HIGH finding exists. |
| `--baseline FILE` | Diff against a baseline; only new findings are reported/counted. Stale entries are noted. |
| `--rules DIR` | Load additional/overriding YAML rules from a directory (same `id` overrides a builtin). |
| `--config FILE` | Explicit config file (`.palisade.toml` format). |
| `--assume-params-untrusted` | **Library mode**: parameters of public (non-underscore) functions become untrusted sources (`param:<name>` in traces). |

File selection: `*.py`/`*.pyi` always; `*.js`/`*.mjs`/`*.cjs`/`*.jsx`/`*.ts`/`*.tsx`
when the `[js]` extra is installed (otherwise skipped with a note).
Always excluded: `.venv`, `venv`, `site-packages`, `.git`, `build`, `dist`,
`node_modules`, caches, plus `.gitignore` patterns. `tests/**`, `test_*.py`,
`*_test.py`, and `conftest.py` are skipped unless `include_tests = true`.
Unparseable files are skipped with a warning, never a crash.

### SARIF / GitHub code scanning

`scan --sarif` emits SARIF 2.1.0 (severity high->error, med->warning, low->note;
sink as the primary location, source and LLM boundary as related locations,
line-shift-resilient `partialFingerprints`). A five-line workflow puts findings
in the GitHub **Security** tab:

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: astral-sh/setup-uv@v5
  - run: uvx palisade-sec scan . --sarif > palisade.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with: { sarif_file: palisade.sarif }
```

## `palisade-sec baseline [PATH]`

Fingerprint current findings so CI fails only on new ones.

| Flag | Effect |
|---|---|
| `--output FILE` | Baseline path (default `<PATH>/.palisade/baseline.json`). |
| `--rules DIR` / `--config FILE` | As in `scan`. |

Fingerprints are `sha256(rule + source file + normalized source snippet +
sink file + normalized sink snippet)` - line-shift resilient by
construction. The file is sorted and deterministic (diff-friendly); commit
it. Duplicate findings collapse to one fingerprint with a count.

## `palisade-sec fix [PATH]`

Write a remediation plan: for each finding, a rule-tailored guardrail plus a
pytest asserting the guardrail blocks the canonical attack and preserves the
happy path. Deterministic templates, fully offline, and the scanned project
is **never modified**.

| Flag | Effect |
|---|---|
| `--output FILE` | Plan path (default `palisade-fixes.md`). |
| `--all` | Cover MED/LOW findings too. |
| `--rules` / `--config` / `--assume-params-untrusted` | As in `scan`. |

Guardrail families: AST allowlist (exec/eval), argv + executable allowlist
(shell), single-SELECT parser check (SQL), host allowlist + private-IP block
(HTTP/SSRF).

## `palisade-sec map [PATH]`

Inventory the codebase's AI surface: LLM call sites (with provider and model),
prompts (static vs dynamic), agent tools (with the capabilities their bodies
exercise), agents/chains, retrieval sites, and dangerous config flags
(`allow_dangerous_code=True`, ...). Deterministic and **offline** - no network,
no key. It is the foundation the judgment checks build on.

| Flag | Effect |
|---|---|
| `--json` | Emit the inventory as JSON (summary + artifacts). |
| `--config FILE` | As in `scan`. |

## `palisade-sec audit [PATH]` (judgment layer)

Run the semantic checks over grounded artifacts and route each to
pass / review / block:

- **excessive agency** - over agent tools the map found: can the tool take an
  irreversible action, is it gated, how much harm if a manipulated model calls it.
- **taint exploitability** - over each verified `source → LLM → sink` finding:
  how realistically exploitable is that specific path, and how severe.

Every question is anchored to a fact the static analyzer verified. Reads the
backend from `.env`; if no key is set it stops with a clear message. An
unverified (generic) backend never emits BLOCK on judgment alone - such a
decision downgrades to REVIEW.

| Flag | Effect |
|---|---|
| `--json` | Emit findings as JSON (`schema_version: 1`). |
| `--ci` | Exit `1` if any finding is a BLOCK decision. |
| `--config FILE` | As in `scan`. |

## `palisade-sec review [PATH]` (judgment layer)

Compose scan + map + the semantic checks + red-team synthesis into one
prioritized report with a **posture score**: a number `0..100` and a named band
(Critical / High / Moderate / Low), derived from the tier counts and printed
with the breakdown beside it. It is a posture over *detected* findings
(`likelihood × impact`), not a safety score. If no judgment backend is
configured, `review` runs taint-only and says so.

`review` judges each finding once per run and emits both the composed posture
and the audit view (`audit_findings` in `--json`) from that single pass, so a
run needs only one judgment pass and `audit`/`review` never disagree within it.
The model is probabilistic, so judged numbers and the posture score vary across
separate runs; the score is deterministic within a run, not across runs.

| Flag | Effect |
|---|---|
| `--json` | Emit the report as JSON (`schema_version: 1`), including the posture block. |
| `--report` | Also write `palisade-review.md`. |
| `--ci` | Exit `1` on a **new HIGH taint** finding (baseline-diffed). Judged signals never gate CI - they are uncalibrated until scored on the corpus. |
| `--baseline FILE` | Baseline to diff `--ci` against. |
| `--config FILE` | As in `scan`. |

## `palisade-sec redteam [PATH]`

Synthesize a targeted adversarial attack suite from the AI System Map, and
optionally execute it against a live target you own.

**Default is advisory and OFFLINE**: it generates attacks aimed at the
discovered tools, prompts, and agents (tool coercion, instruction override,
data exfiltration, jailbreak, system-prompt leak) but does NOT run them.

| Flag | Effect |
|---|---|
| `--json` | Emit the suite (or, with `--execute`, the run report) as JSON. |
| `--variants N` | Attack variants per target (1-5). |
| `--execute` | Fire the suite at a live target. Requires `--approve`. |
| `--approve` | Required with `--execute`: you authorize firing adversarial inputs. |
| `--target URL` | Target endpoint (or set `PALISADE_REDTEAM_TARGET`; key via `PALISADE_REDTEAM_KEY`). |
| `--ci` | With `--execute`: exit `1` if any attack lands. |
| `--config FILE` | As in `scan`. |

Execution drives the endpoint **you** provide, in your environment - Palisade
never executes your code. It scores landed attacks with the judgment backend
from `.env` (deterministic tool-invocation checks plus a model for behavioral
judgment). Run it only against systems you own and are authorized to test.

## Judgment configuration

`audit` and `review` read their backend from environment variables, loaded from
a local `.env` (see [`.env.example`](../.env.example)). Keys are read from the
environment only and are never logged.

| Variable | Meaning |
|---|---|
| `PALISADE_JUDGE_BACKEND` | `typesafe` (default) or `openai_compatible`. |
| `PALISADE_JUDGE_ENDPOINT` | Base URL. Defaults to the TypeSafe API for `typesafe`; required for `openai_compatible`. |
| `PALISADE_JUDGE_MODEL` | Model id. Defaults to `jev-latest` for `typesafe`; required for `openai_compatible`. |
| `TYPESAFE_API_KEY` | Key for the `typesafe` backend. |
| `PALISADE_JUDGE_API_KEY` | Key for the `openai_compatible` backend. |

Install the extra with `pip install 'palisade-sec[judge]'`. **TypeSafe** returns
calibrated answers; a generic OpenAI-compatible endpoint is validated against a
strict schema and treated as best-effort/unverified, so it can never BLOCK or
raise a Critical posture on judgment alone.

## Inline suppressions

Some findings cannot be fixed today: the code is genuinely sandboxed, the
risk is accepted, or the fix is scheduled. Without a way to silence one,
"one unfixable finding disables the tool" and the whole scanner gets removed
from CI. Suppress it in place instead:

```python
exec(code)  # palisade: ignore[PI-EXEC] - runs in a locked-down sandbox
```

```javascript
eval(code); // palisade: ignore[PI-EXEC] - input is schema-validated upstream
```

| Form | Effect |
|---|---|
| `# palisade: ignore[PI-EXEC]` | silences that rule on this finding |
| `# palisade: ignore[PI-EXEC,PI-SQL]` | silences any of the listed rules |
| `# palisade: ignore` | silences every rule on this finding |
| `- reason` or `: reason` after the brackets | recorded and reported |

The comment goes on the **sink line**, or the line directly above it. `#`
and `//` are both accepted, so the same syntax works in Python and JS/TS.
Rule ids are case-insensitive.

Suppressions are deliberately loud, because a silent one is how a
vulnerability quietly comes back:

- suppressed findings are **counted**, not discarded, and reported in the
  terminal summary and in `summary.suppressed_inline`
- each one appears in the `suppressions` array of `--json` with its rule,
  location, severity and reason
- a comment that stops matching anything is reported as **stale**, so dead
  suppressions get cleaned up instead of masking a future finding

A suppression lives in the code being scanned, so anyone who can edit the
code can silence a finding. That is the same trust model as `# noqa`, and
the reason suppressions are counted and attributable rather than invisible.
Review them in code review like any other change.

## Configuration

`pyproject.toml` under `[tool.palisade]`, or the same keys in
`.palisade.toml` at the scan root (`--config` overrides discovery). Invalid
config → warning + defaults, never a crash.

```toml
[tool.palisade]
paths_ignore = ["migrations/*", "sandbox/*"]   # glob patterns, relative to root
include_tests = false                          # scan tests/** too
max_hops = 3                                   # inter-procedural depth bound
assume_params_untrusted = false                # library mode default
rules_dir = "security/palisade-rules"          # extra rules directory
```

CLI flags override config; an explicit `assume_params_untrusted=False` from
an API caller overrides both.

## JSON schema

`scan --json` emits one document. `schema_version` gates compatibility -
parse defensively on any other value.

```jsonc
{
  "schema_version": 1,
  "tool": "palisade-sec 0.3.2",
  "summary": {
    "files_scanned": 6,
    "high": 4, "med": 1, "low": 0,
    "baseline_suppressed": 0,         // known findings hidden by --baseline
    "suppressed_inline": 0            // findings silenced by `palisade: ignore`
  },
  "suppressions": [                    // each silenced finding, never hidden
    {"rule": "PI-EXEC", "file": "app.py", "line": 42,
     "severity": "high", "reason": "sandboxed", "suppressed_at": 42}
  ],
  "findings": [                        // sorted: severity, file, line, rule
    {
      "rule": "PI-EXEC",
      "title": "Prompt injection reaching code execution",
      "severity": "high",              // high | med | low
      "confidence": "HIGH",            // HIGH | MEDIUM | LOW (path directness)
      "risky_partial_defense": false,  // true when downgraded (see below)
      "file": "app.py",                // sink location = finding location
      "line": 64,
      "fingerprint": "9f2c4a1b8e3d5f07",   // baseline identity, line-independent
      "count": 1,                      // duplicates collapsed into this entry
      "trace": {
        "source": { "file": "app.py", "line": 56, "snippet": "spec = request.json[\"spec\"]", "matched": "request.json" },
        "llm":    { "file": "app.py", "line": 57, "snippet": "resp = client.chat.completions.create(", "matched": "chat.completions.create" },
        "sink":   { "file": "app.py", "line": 64, "snippet": "exec(code)", "matched": "exec" }
      },
      "partial_defenses": [            // non-empty ⇒ severity was downgraded to med
        { "pattern": "is_blocked_code", "kind": "partial_defense", "file": "app.py", "line": 95 }
        // kind: "partial_defense" (denylist/confirmation gate)
        //     | "unverified_sanitizer" (sanitizer in name only)
      ],
      "attack": "...", "fix": "...", "references": ["CVE-...", "..."]
    }
  ],
  "skipped":  ["broken.py: parse error, file skipped (...)"],
  "warnings": ["invalid rule file skipped: bad.yaml: ..."],
  "notes":    ["1 JS/TS file(s) skipped - install ... palisade-sec[js] ..."]
}
```

Notes for consumers:

- `--json` always includes **all** severities; the HIGH-first display filter
  applies to terminal output only.
- In library mode, `trace.source.matched` is `param:<name>`; for route
  handlers it's the matched source pattern (`request.json`, `req.body`, …).
- `notes` may include an inter-procedural truncation notice on very deep
  call chains - recall, not precision, is what truncation affects.

## Baseline file format

```jsonc
{
  "schema_version": 1,
  "tool": "palisade-sec 0.3.2",
  "findings": {
    "<fingerprint>": { "rule": "PI-EXEC", "file": "app.py", "severity": "high", "count": 1 }
  }
}
```

Sorted by fingerprint; safe to merge in git. A missing or corrupt baseline
degrades gracefully: a warning, and all findings treated as new.
