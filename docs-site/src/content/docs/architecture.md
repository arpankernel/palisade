---
title: "Architecture"
description: "Frontends → taint IR → engine → rules, and the precision & safety contracts."
---

How Palisade turns source text into precise findings - and why it's shaped
this way.

## The spine

```
                ┌────────────── language frontends (pluggable) ──────────────┐
  source ────▶  │  Python (stdlib ast)      JS/TS (tree-sitter, [js] extra)  │
                └───────────────────────────┬─────────────────────────────────┘
                                            ▼
                     Normalized Taint IR - language-neutral nodes:
                     assignments, calls (dotted paths), string joins,
                     collections, branches, functions, classes
                                            ▼
                ┌──────────── language-agnostic engine ────────────┐
                │  taint propagation (bounded inter-procedural)     │
                │  sanitizer resolution & body verification         │
                │  partial-defense downgrade · confidence scoring   │
                └───────────────────────────┬──────────────────────┘
                                            ▼
      YAML rules (data) ──▶ findings ──▶ dedup ──▶ baseline diff ──▶
                     emitters (terminal / JSON / markdown) ──▶ exit code
```

Three load-bearing decisions:

1. **Frontend/IR split.** A frontend's only job is lowering source into the
   IR. The engine never sees a Python `ast` node or a tree-sitter node. This
   is proven, not aspirational: the JS/TS frontend landed with **zero engine
   changes**, and the same YAML rules match both languages.
2. **Rules are data.** Sources, LLM signatures, sinks, sanitizers, and
   partial defenses are dotted-path patterns in YAML, validated by a
   pydantic schema. New framework coverage is a rule PR, never an engine PR.
3. **Precision over recall, mechanically enforced.** Every claim below has a
   must-NOT-flag test twin in the suite; the false-positive tests are the
   most important tests in the repo.

## Package layout

```
src/palisade_sec/
├── frontends/          # ast_python.py · tree_sitter_js.py  (source → IR)
├── ir/                 # the normalized taint IR (model.py)
├── engine/             # analyzer.py (taint), findings.py, taint.py
├── rules/              # 5 builtin YAML rules + pydantic schema + loader
├── report/             # terminal (rich) / json / markdown emitters
├── scanner.py          # file discovery, config, frontend dispatch
├── baseline.py         # fingerprints, baseline diff
├── fix.py              # deterministic remediation-plan templates
└── cli.py              # Typer CLI: scan · baseline · fix
```

## The IR in one screen

Frontends emit a deliberately small vocabulary (`ir/model.py`):

- **Expressions** - `Const`, `VarRef` (dotted path, alias-resolved),
  `Member`, `Call` (dotted `func_path`, args/kwargs, receiver), `StrJoin`
  (f-strings, `%`, `.format`, `+`, `.join`, template literals),
  `Collection`, `Unknown` (taint = union of children).
- **Statements** - `Assign` (targets incl. `self.x` and `+x` augment),
  `Return` (with `raises` flag), `IfBranch` (with guard metadata:
  test names/calls, negation, literal-membership, terminates), loops,
  try/with blocks.
- **Definitions** - `FuncDef` (params, decorators, membership-test flag),
  `Module` (import aliases, class bases).

Anything a frontend can't express folds into `Unknown`, which propagates
taint conservatively. Import aliases are resolved at lowering time, so
`import subprocess as sp; sp.run(...)` reaches the engine as
`subprocess.run` - in both languages (`const {exec} = require("child_process")`
becomes `child_process.exec`). In JS, `this` is spelled `self` so class-field
tracking and hierarchy resolution are shared.

## How a finding is born

Walk the tutorial's `/report` route through the engine:

1. **Entry.** Every function is analyzed as an entry point with clean
   parameters (plus seeded param taints in library mode or for
   route-decorated handlers).
2. **Source.** Evaluating `request.json["spec"]` matches the rule source
   pattern `request.json` (dotted-prefix matching: `req.body.q` matches
   `req.body` too). The variable now carries a `SOURCE` taint that remembers
   its own file:line and snippet.
3. **LLM boundary.** `client.chat.completions.create(...)` matches an
   `llm_signatures` pattern. Because a `SOURCE`-tainted value is among its
   arguments (even nested inside `messages=[{"content": spec}]`), the call's
   result carries an `LLM` taint - provenance of both the source and the
   LLM call site travels with it.
4. **Propagation.** Taint flows through assignments, string building,
   collections, comprehensions, `await`, returns, `self.x` fields,
   accumulators (`parts.append(tainted)`), `json.loads(...)["cmd"]`, and
   bounded inter-procedural calls (default 3 hops; project-local functions
   and `self.` methods are resolved, including through class hierarchies
   when unambiguous; abstract stubs propagate instead of swallowing taint).
5. **Sanitizer resolution.** A call matching a sanitizer pattern is judged,
   not trusted:
   - `trusted: true` patterns (pydantic `model_validate`, marshmallow
     `schema.load`, `shlex.quote`, …) - suppress on name match.
   - Name-heuristic patterns (`validate…`, `sanitize…`, `…allowlist`) -
     suppress **only if the resolved body shows a real validation shape**
     (a membership test, a guard branch that raises/returns, a raise
     anywhere, an `re.fullmatch`-style call, or one level of delegation to
     such a body). Otherwise the taint keeps flowing, tagged
     `unverified_sanitizer` → the finding lands as **MED "risky"**.
   - Full sanitizers also include `int()`/enum casts and literal-membership
     guards (`if verb in ("list", "status")`).
6. **Partial defenses never suppress.** Denylists and confirmation gates
   (`is_blocked(...)`, `confirm(...)`) tag the taint and downgrade the
   eventual finding to MED - because PAL's denylist and Open Interpreter's
   gate were bypassed in the wild.
7. **Sink.** `exec(code)` matches a sink pattern. Sink specs carry shape
   guards: `taint_args: [0]` (only `exec`'s *code* argument is dangerous -
   a tainted globals dict is not), `require_kwargs: {shell: true}`
   (`subprocess.run([...])` without it is safe), `safe_if_extra_args`
   (parameterized `execute(q, params)` is safe). A sink-named call that
   resolves to a real project function is *followed* instead - the true
   sink inside beats the name heuristic.
8. **Emission & dedup.** The finding carries the full trace from the taint's
   own provenance. Duplicates collapse by fingerprint; **one vulnerability
   (same source → same sink) is one finding even when several rules match**
   - the most specific rule wins.

Confidence maps from hop count (0–1 → HIGH, 2 → MEDIUM, ≥3 → LOW); severity
comes from the rule, downgraded to MED when partial defenses or unverified
sanitizers are on the path.

## Precision decisions (the "won't flag" contract)

| Situation | Verdict | Why |
|---|---|---|
| Constant developer prompt → LLM → exec | silent | no untrusted source; taint requires one |
| Untrusted input → sink with **no LLM** | silent | out of contract - that's Bandit's finding, not Palisade's |
| `subprocess.run([...])` arg list | silent | safe sink shape |
| `cursor.execute(q, params)` / `pool.query(text, values)` | silent | parameterized |
| LLM output only logged/printed/returned | silent | not a sink |
| pydantic/marshmallow validation on path | silent | trusted sanitizer tier |
| Verified project sanitizer (raises/allowlists) | silent | body-verified |
| Denylist / confirmation gate | **MED risky** | bypassed in real CVEs |
| Sanitizer in name only (cosmetic transform) | **MED unverified sanitizer** | Vanna CVE-2024-5565 shipped through one |
| `tests/**`, `conftest.py`, `.venv`, `.gitignore`d | skipped | configurable (`include_tests`) |

## The judgment layer (optional, bring-your-own endpoint)

The taint engine is deterministic. On top of it sits an optional judgment layer
that answers questions the engine cannot decide by dataflow alone. It is reached
only by `map`, `audit`, and `review`, never by `scan`, and only `audit`/`review`
call out.

```
  IR ──▶ PROBE (map): inventory the AI surface (offline, deterministic)
  taint findings ─┐
  agent tools ────┼─▶ CHECKS build grounded questions from verified facts
                  │       excessive_agency (tools) · taint_exploitability (paths)
                  ▼
             JudgeBackend.ask(state, questions)   # one batched call per artifact
              ├─ TypeSafe: calibrated typed answers (verified)
              └─ OpenAI-compatible: strict-JSON validated against a schema
                                     (best-effort, unverified)
                  ▼
             decision (pass/review/block) ──▶ review composes a posture
```

Three properties keep it honest:

1. **Grounded.** A check only ever asks about an artifact the IR verified exists
   (a real tool, a real `source → LLM → sink` path). The state sent to the
   endpoint is that verified fact, not raw files.
2. **Two adapters, one interface.** `judge/` defines a `JudgeBackend` with
   backend-neutral `Question`/`Answer` types. TypeSafe returns calibrated answers
   (`verified=True`); a generic OpenAI-compatible endpoint is validated against a
   pydantic schema and labelled best-effort (`verified=False`).
3. **The unverified ceiling.** An unverified backend can never emit a BLOCK on
   judgment alone (it downgrades to REVIEW), never move a deterministic finding's
   risk, and never manufacture a Critical posture. The same rule is enforced at
   the finding level and again at the aggregate.

The exploitability and posture signals are **uncalibrated until scored on the
corpus**; the deterministic scanner's published precision is independent of them.

Judged output is **deterministic within a single run and non-deterministic
across runs**. `review` performs one judgment pass and exposes both the audit
view (`audit_findings`) and the composed posture from it, so within a run they
never disagree. Because the model is probabilistic, two separate invocations can
score the same finding differently; the posture score is not stable run-to-run,
and nothing here claims it is.

## Safety contract (non-negotiable)

- **The scanner never executes, imports, or evals scanned code.** Parsing
  only (`ast.parse` / tree-sitter). A live test plants a file whose
  module-level code writes a marker and asserts the marker never appears.
- **`scan` makes no network calls** and needs no API key, account, or
  telemetry. Nothing leaves your machine.
- Writes are limited to `.palisade/` and explicitly requested output files.
- A file that fails to parse is skipped with a warning - never a crash.
  Invalid rules and configs are reported and skipped (pydantic-validated).

## Scale characteristics

Measured on real repos (see [proof-scans.md](proof-scans.md)): 1,576 mixed
Python+TypeScript files (Langflow 1.2.0, backend + frontend) in ~36 s, zero
crashes, zero skipped files, zero false positives. Inter-procedural depth is
bounded (default 3 hops, configurable) and truncation is reported honestly
in the scan notes.

## Known limits (documented, not hidden)

- Receiver-name LLM signatures (`chain.run`, `llm.predict`) match by
  variable naming convention; unusual names need a one-line custom rule.
- Many-provider abstract dispatch (ten subclasses implementing
  `submit_prompt`) stays unresolved by design - ambiguity is not resolved by
  guessing. The `PI-FRAMEWORK-EXEC` wrapper signatures cover the common
  cases.
- Fully dynamic pipeline-object dataflow (PandasAI v2's step runner) is
  beyond bounded static taint; framework-specific rules are the pragmatic
  path.
- Sanitizer body verification is a heuristic - it judges shape, not
  semantics. It errs toward flagging (downgrade, never silence).
- The `map` command resolves a literal `model=` argument only; a model id held
  in a variable or module constant is reported as `?`. Offline-map only; it does
  not affect taint findings or the judgment layer.
