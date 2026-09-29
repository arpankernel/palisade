# The judgment layer: Palisade toward an AI Safety Engineer

> **Reconciled against the code at 0.6.0 (2026-09-30).** Every status claim below
> was checked against `src/`, and the sections that had drifted are marked
> **[reconciled]** with the file that settles them. This document is the spec and
> the spec gets ahead of the code: where it does, the gap is now stated rather
> than implied.
>
> Shipped today:
> - **SEE (static, offline)** — `palisade-sec map`: inventory of the AI surface,
>   6 artifact kinds (`semantic/inventory.py`).
> - **DETECT (static, offline)** — `palisade-sec scan`: **6** deterministic taint
>   rules, precision 1.000 / recall 0.200 on the pinned corpus.
> - **JUDGE (static, keyed)** — `palisade-sec audit`: **2 of ~9** checks —
>   excessive agency (`semantic/audit.py`) and taint-path exploitability
>   (`semantic/exploitability.py`). Both landed in v0.5.0.
> - **COMPOSE (keyed, degrades)** — `palisade-sec review`: one posture report over
>   taint + judged signals (`semantic/review.py`, `semantic/risk.py`). Runs
>   taint-only without a key.
> - **PROBE·ACTIVE** — `palisade-sec redteam`: Map-driven attack suite, **6
>   families**; synthesis offline, execution gated on `--approve`.
> - **PROVE** — per-check calibration measured and published
>   (`corpus/judgment/RESULTS.md`), including one honestly-excluded weak signal.
>
> **Backend-agnostic since 0.6.0.** This document was written when TypeSafe was
> the only backend and the extra was `[semantic]`. Today the extra is **`[judge]`**
> (`[semantic]` kept as an alias), three backends are supported — `typesafe`,
> `anthropic` (native Messages API), `openai_compatible` — and keys are set with
> **`palisade-sec connect llm`**, not only `TYPESAFE_API_KEY` in a `.env`. TypeSafe
> remains the default and the only backend treated as `verified`; everything else
> is `verified=False` and can never BLOCK on judgment alone. Read
> `docs/judgment-layer.md` for the user-facing version of this.
>
> Scope owner: code lands under `src/palisade_sec/semantic/` (judged checks) and
> `src/palisade_sec/judge/` (backends, types, calibration).

## The bigger arc: the hire, not the tool

Positioned like an "AI CMO" or "AI PM" agent, Palisade is the **AI Safety
Engineer/Officer** a company plugs in. The reference job description
(`docs/ai-safety-engineer-role.md`) *is* the product spec. A real
safety engineer has three senses; a linter has one:

| Sense | What | When | Status |
| --- | --- | --- | --- |
| **Static** | read code → map + checks | pre-commit / CI | ✅ `map`, `scan`, `audit` (2 checks), `review` |
| **Active** | *run* the system with adversarial inputs | pre-ship | 🚧 `redteam` (synth ✅; execution gated, adapters thin) |
| **Runtime** | *watch* production, trace incidents | in-prod | ⬜ nothing shipped |

The senses form the loop that makes it an engineer, not a scanner: **SEE** →
**PROBE** (red-team/evals) → **GUARD** (generate guardrails) → **WATCH**
(runtime) → incident → new static check + regression test → back to SEE.

**Two different things are called PROBE in this document [reconciled].** They are
distinct modules and both exist:

- **PROBE (harvest)** — `semantic/probe.py`, deterministic and offline: lowers IR
  into safety artifacts (tools + the capabilities in their bodies) for a judge to
  assess. This is the §3/§7 sense.
- **PROBE·ACTIVE** — `semantic/redteam.py`: synthesizes adversarial payloads from
  the Map and, only with `--execute --approve`, sends them at a target *you*
  supply. This is the banner sense.

Where this document says "PROBE" without a qualifier below, it means the harvest.

**Autonomy posture (decided):** advisory + approval gates. Palisade proposes
attacks, guardrails, and fixes; a human approves any mutating or production
action. `redteam.run()` enforces this in code (`approved=True` required). A
safety product that models safe autonomy is a credibility asset, not a
limitation.

### JD → capability map (the "how")

| JD duty | Palisade capability | Sense | Status |
| --- | --- | --- | --- |
| Evaluations (harmful output, jailbreak, tool-use safety) | eval engine, TypeSafe scoring | active | 🚧 |
| Red-teaming / adversarial testing | `redteam` synth + gated runner | active | ✅ synth / 🚧 exec adapters |
| Runtime guardrails (I/O filter, policy, sandbox, circuit-break) | guardrail generator + runtime SDK | runtime | ⬜ |
| Monitoring & observability | runtime hooks/sidecar → posture dashboard | runtime | ⬜ |
| Safety cases | evidence assembler (map+evals+redteam+guardrails) | all | ⬜ |
| Incident RCA + regression tests | incident agent; extend `fix` | runtime→static | ⬜ |

**Trust guardrails for going dynamic:** execution uses a target the *user*
provides (their env, their keys) — Palisade never executes the customer's
codebase; runtime monitoring must be opt-in and self-hostable (don't lose the
"nothing leaves your machine" trust); scope is *infrastructure that
operationalizes safety*, not doing alignment research.

## Completeness model: the six things a safety engineer does

Going from "guardrails-as-a-service" (a runtime message filter) to an "AI safety
engineer" (reviews the whole system in code, before ship) means doing the whole
job, not one check:

**[reconciled]** — counts and statuses below are from the code at 0.6.0.

| # | Verb | Meaning | Status |
| --- | --- | --- | --- |
| 1 | **SEE** | inventory every place AI is used | ✅ `map`, offline, 6 artifact kinds |
| 2 | **JUDGE** | assess every failure mode | 🚧 **2 of ~9** checks + **6** taint rules |
| 3 | **DECIDE** | rank by risk, apply *your* policy | 🚧 thresholds in code (`semantic/policy.py`); **no file loading yet** |
| 4 | **FIX** | propose guardrail + test | ✅ taint (`fix`); ⬜ semantic |
| 5 | **ENFORCE** | CI gate, baseline, posture report | ✅ `scan/review --ci` + baseline + posture in `review`; `audit --ci` BLOCK |
| 6 | **PROVE** | calibrated, grounded, not hallucinated | ✅ grounded harvest; ✅ **per-check calibration measured** (`corpus/judgment/RESULTS.md`), ⬜ not yet a CI gate |

The two shipped checks are **excessive agency** (`semantic/audit.py:101`) and
**taint-path exploitability** (`semantic/exploitability.py`), both v0.5.0, both
run by `audit` and composed by `review`.

**Complete v1 target:** `map` (done) + ~5 checks (**2 done**) + one `review`
report merging taint + semantic with a posture score (**done**) + per-check
calibration (**done for the 2 shipped checks; needs a case per new check**).

### The number this document should not bury [reconciled]

The deterministic core measures **precision 1.000, recall 0.200** — of 10
hand-verified injection paths in the pinned corpus it finds 2. Breadth (checks
3–9) widens the surface while that holds. The three named recall gaps at the top
of `docs/roadmap.md` outrank new checks, and a fourth was found while triaging
PR #17 (container entry points in agent graphs). "The AI Safety Engineer you
hire" is the destination; today's defensible claim is a precise detector for
one failure mode, plus a red-team suite and an advisory judgment layer.

## 1. Why

Palisade today is a **sensor for one failure mode**: untrusted input → LLM →
dangerous sink, found by deterministic taint analysis. That core is precise
(precision 1.000 on the benchmark corpus), offline, and free — and it must stay
exactly that.

But most "AI safety" questions a real engineer asks are **not** taint questions.
"Can this agent tool delete data without confirmation?" "Does this prompt embed a
secret?" "Is this sanitizer actually neutralizing injection, or just renaming a
variable?" These need *semantic judgment*, not dataflow reachability.

[TypeSafe](https://docs.typesafe.ai) supplies exactly that missing half: its
**System One** models turn structured state into **calibrated typed judgments**
(`Noul` probabilities, `Score` severities, `Choice` routings) that code can act
on — not prose, not a chat completion to parse.

The thesis of this integration:

> **Palisade = the eyes. TypeSafe = the judgment.**
> Palisade already lowers messy source into a language-neutral IR with full
> provenance. That IR *is* the `state` TypeSafe wants. We feed TypeSafe
> **verified facts** ("this untrusted value reaches this exec; the sanitizer body
> is literally this") and ask a narrow question. Grounded evidence + a calibrated
> probability = a decision you can gate CI on.

That grounding is the moat. Every other AI code reviewer feeds raw files to an LLM
and gets confident hallucinations. We only ever ask TypeSafe about artifacts the
IR verified exist.

## 2. The non-negotiable constraint

Palisade's README headline is *"No API key. No signup. No network calls. Pure
static analysis."*, enforced by a live test (`tests/test_self_security.py`).

**TypeSafe is a hosted API** (network + `TYPESAFE_API_KEY` + code snippets leave
the machine). Therefore:

- **`scan` never changes.** It stays offline, keyless, precision-1.000. This is
  the wedge and the trust. Do not touch its contract. **Still true at 0.6.0**, and
  now enforced harder: a test asserts the scanner does not even *import* the
  connected code or `urllib.request`, and it fails under mutation.
- The semantic layer is a **separate tier**: the `audit` subcommand, behind an
  optional extra, loud about what leaves the machine.

**[reconciled] — the extra and the key.** This section said extra
`palisade-sec[semantic]`, key from the environment only, TypeSafe only. At 0.6.0:

| Then | Now |
|---|---|
| `pip install 'palisade-sec[semantic]'` | **`[judge]`** is the name; `[semantic]` is kept as an alias |
| `TYPESAFE_API_KEY` in the environment | any of `TYPESAFE_API_KEY` / `ANTHROPIC_API_KEY` / `PALISADE_JUDGE_API_KEY` |
| environment only | also **`palisade-sec connect llm`** → OS keychain, or a `0600` file; also a `.env` in the cwd. Environment always wins |
| TypeSafe only | `typesafe`, `anthropic` (native), `openai_compatible` |
| — | a non-default endpoint from a `.env` combined with a shell key is **refused** (split-origin guard, `judge/config.py`) |

The trust properties survived the widening: only TypeSafe is `verified=True`; a
bring-your-own backend is `verified=False`, is labelled unverified in every
output, and **cannot BLOCK on judgment alone**.
- The `--ci` HIGH gate keeps using **deterministic** findings. A probability can
  *add* an advisory finding; it can never silence a deterministic HIGH.

## 3. The re-designed spine

```
                 frontend → IR   (unchanged: Python ast, JS tree-sitter)
                              │
        ┌─────────────────────┴──────────────────────┐
        ▼                                             ▼
  EVIDENCE ENGINE (deterministic)            PROBE  (new, deterministic)
  taint: source → LLM → sink                 harvests safety-relevant artifacts
  sanitizer shape heuristic                  from the SAME IR:
  confidence by hop count                    • agent tools (FuncDef + decorators)
                                             • prompt templates (StrJoin)
                                             • LLM call configs (Call kwargs)
                                             • dangerous flags/defaults
        └─────────────────────┬──────────────────────┘
                              ▼
                   JUDGE  (TypeSafe System One — opt-in, keyed)
             batched Noul / Score / Choice over each artifact's state,
             driven by POLICY (org-editable criteria + thresholds)
                              ▼
              DECISION: pass · review · block   (per artifact, per policy)
                              ▼
                   terminal / JSON / CI gate
```

Two new modules; the evidence engine and rules-as-data are untouched. The
**PROBE** is the unlock: taint only ever *used* the source→sink slice of the IR;
the PROBE exposes the rest of the AI-relevant surface to a judge.

### Module layout

**[reconciled] — this was the 4-module plan; the layer grew to 13 files plus a
subpackage, and the backends moved out into their own package.**

```
src/palisade_sec/semantic/          # the judged checks and everything offline
├── inventory.py        # SEE: IR → AI System Map (llm_call, prompt, tool,
│                       #      agent, retrieval, config_flag)      [map]
├── probe.py            # PROBE (harvest): IR → tools + capabilities
├── policy.py           # thresholds + editable criteria (defaults only, in code)
├── judge.py            # Judge protocol, batching, graceful degradation
├── audit.py            # check 1: excessive agency; decide(); AuditReport
├── exploitability.py   # check 2: taint-path exploitability
├── review.py           # COMPOSE: taint + judged → one report      [review]
├── risk.py             # risk scoring + posture
├── redteam.py          # PROBE·ACTIVE: 6 attack families, gated execution
├── walk.py             # shared IR traversal
└── agents/             # PI-AGENT-HANDOFF: the 6th taint rule, deterministic
    ├── graph.py        #   build the agent graph from IR
    └── findings.py     #   untrusted input → handoff → dangerous-tool agent

src/palisade_sec/judge/             # backends and the judged contract
├── types.py            # NoulQ / ScoreQ / ChoiceQ, JudgeResult
├── base.py             # JudgeBackend protocol; `verified` flag
├── config.py           # backend selection, key resolution, split-origin guard
├── typesafe.py         # the calibrated, verified backend (default)
├── anthropic.py        # native Messages API                      [0.6.0]
├── openai_compatible.py# OpenAI / vLLM / Ollama / LiteLLM
└── calibration.py      # Brier, exact/within-1 accuracy, vacuity guard
```

`scanner.py`'s shared lowering refactor **shipped**: `lower_project(...)` at
`scanner.py:248`, used by both `run_scan` and the semantic path, with no
behaviour change to `scan`.

## 4. The check catalog (grows over time)

Each check reuses IR artifacts the PROBE already has and maps to a TypeSafe
primitive and a real failure class (OWASP LLM Top-10 / MITRE ATLAS).

**[reconciled] — 2 of the 8 rows below are shipped; the status column is new.**

| Check | IR artifact → `state` | Primitive | Judgment | Status |
|---|---|---|---|---|
| **Excessive agency** (LLM08) | tool `FuncDef` + capabilities found in body | Noul + Score | Can this tool take an irreversible/destructive action with no confirmation? | ✅ v0.5.0 |
| **Taint-path exploitability** | the verified `source → LLM → sink` trace | Noul + Score | Is this path actually exploitable, and how bad? | ✅ v0.5.0 |
| Sanitizer really neutralizes (LLM01) | sanitizer body + sink kind + trace | Noul + Score | Does this body neutralize injection for this sink? (Vanna case) | ⬜ — **scope shrank**, see below |
| Hidden LLM call sites (recall) | model-shaped `Call` nodes | Noul | Is this an LLM invocation? (`chain.run`, custom wrappers) | ⬜ — overlaps named recall gap (b) |
| Unresolved dynamic dispatch (recall) | ambiguous method + hierarchy | Noul | Does this forward untrusted input to a model/sink? | ⬜ — overlaps named recall gap (c) |
| Insecure output handling (LLM02) | LLM-tainted value → non-exec sink | Noul | Is model output trusted downstream without validation? | ⬜ |
| Secrets/PII in prompts (LLM06) | prompt `StrJoin` templates | Noul + Score | Does this prompt embed credentials/PII or leak the system prompt? | ⬜ — `map` already harvests the templates |
| Unsafe framework defaults | `Call` kwargs (`allow_dangerous_code=True`) | Noul | Is this an unsafe default in context? | ⬜ — `map` already flags them deterministically (`config_flag`) |
| Missing human-in-the-loop | high-harm sink w/o confirmation gate | Noul | Should this require human approval before executing? | ⬜ — partly covered by the `gated` signal, which is **known-weak** |

### Why the sanitizer check shrank [reconciled]

0.5.1 solved most of this deterministically instead. `_body_validates()`
(`engine/analyzer.py:921`) now silences a finding **only** for allowlist shapes:
membership where the input is the element, an AST node-type `isinstance`
allowlist, an enum-literal guard, or a strict whole-string validator
(`re.fullmatch`). Denylists, length and emptiness checks, and a bare `raise` no
longer verify anything — they leave the finding as a MED
`unverified_sanitizer` rather than silencing it.

So the judged version is no longer "decide if this sanitizer works". Everything
unrecognised is already downgraded, never silenced, and the remaining question is
narrower: *can this MED be promoted or closed?* Worth building, much smaller than
this row implies, and no longer on the critical path.

## 5. The policy engine — "for *your company*"

Straight from TypeSafe's guardrails cookbook: the **same assessment, different
routing per org, via editable policy**. This is what turns a tool into a hired
engineer.

```yaml
# .palisade/policy.yaml — your company's AI-safety conscience, as data
semantic:
  checks:
    excessive_agency:
      criteria:
        irreversible: "deletes data, sends money, or emails customers"
      action_threshold: 0.60    # block in CI above this
      review_threshold: 0.30    # else flag for human review
      severity_block: 2         # harm >= this turns review into block
```

Same TypeSafe judgment; a fintech sets `severity_block: 1`, a hobby project sets
`3`. The criteria are editable English, so your policy *is* the prompt.

> **[reconciled] — the YAML above does not load yet.** `semantic/policy.py` has
> the model (`CheckPolicy`: `action_threshold` 0.60, `review_threshold` 0.30,
> `gate_threshold` 0.50, `severity_block` 2, plus `criteria`) and
> `default_policy()`, and `audit`/`review` route through it — but there is **no
> reader** for `.palisade/policy.yaml` or `[tool.palisade.semantic]`. Every run
> uses the defaults. Changing thresholds today means editing Python.
>
> This is the single largest gap between this document and the code, and it is
> the one that matters most for the "hired engineer" framing: without file
> loading, the policy is *ours*, not the customer's. It is small — a pydantic
> model that already exists plus a loader and a config test — and it should
> probably come before check #3.

## 6. What stays sacred

1. **Don't cannibalize the wedge.** Free offline `scan` is why people trust
   Palisade. Semantic is a tier above, never a replacement.
2. **Grounding is the whole game.** Only ask TypeSafe about artifacts the IR
   verified. Never feed raw files "to be thorough."
3. **Calibration is a per-check cost.** Every check needs labelled examples in the
   26-repo corpus to set thresholds honestly, and the CI precision gate must
   extend to the semantic tier.
4. **Batch aggressively.** One `system_one()` call per artifact carrying all its
   questions (parallel-questions cookbook: ~12× cost / 10× speed).
5. **Be loud about egress.** `audit` prints exactly which snippets leave the
   machine; the key is env-only.

## 7. First slice: excessive-agency check — SHIPPED v0.5.0

**[reconciled]** — this section was written in the future tense as a plan. It
shipped in v0.5.0 (`3867dfb`) and reads as built, below. It was the end-to-end
proof of the spine, chosen because it needs **zero taint** — it validated the
PROBE → JUDGE → DECISION path on its own.

- **PROBE** (`probe.py`, deterministic, fully unit-tested offline): find agent
  *tools* (functions whose decorators match a small configurable set — `tool`,
  `*.tool`, `function_tool`, …) and, inside each tool body, the **capabilities**
  it exercises (shell, code-exec, file-write/delete, network, db-write, payments,
  email, secrets) by matching `Call.func_path` against capability patterns. Only
  tools with ≥1 capability are sent to the judge (cost gate).
- **JUDGE** (`judge.py`): for each such tool, one batched `system_one()` call:
  - `Noul irreversible` — can this tool take an irreversible/destructive action?
  - `Noul gated` — does it require confirmation/human approval first?
  - `Score harm` (0–3) — harm if a manipulated model invokes it.
- **DECISION** (`audit.py`, policy-driven): `block` when
  `irreversible ≥ action_threshold AND gated < gate_threshold AND harm ≥
  severity_block`; `review` at the lower thresholds; else `pass`.

Testing: the PROBE is deterministic and tested with offline fixtures. The judge
is behind a `Judge` protocol so `audit` is tested with a `FakeJudge` — **no live
API calls in the test suite**. Running it for real needs `pip install
'palisade-sec[judge]'` and a key via `palisade-sec connect llm` (or an
environment variable).

## 8. Sequence after this slice — [reconciled]

The original three next steps, as they actually stand:

1. ~~Sanitizer semantic verifier~~ — **overtaken, scope shrank.** 0.5.1 solved
   the dangerous half deterministically: only allowlist shapes silence a finding,
   so nothing unrecognised is silenced any more. See "Why the sanitizer check
   shrank" in §4. What remains is a narrower promote-or-close question on the MED
   tier.
2. **Policy engine file loading** — *still open, and now the biggest gap.* The
   model exists; the reader does not. See the note in §5.
3. **Corpus eval harness for the judged tier** — *half done.* `scripts/calibrate.py`
   and `judge/calibration.py` exist (precision/recall/Brier per Noul signal,
   exact and within-1 accuracy per Score signal, plus a vacuity guard that fails
   a signal with zero cases). Measured results are published in
   `corpus/judgment/RESULTS.md`: `exploitable` and `irreversible` at 1.00
   precision/recall, `severity`/`harm` within ±1 tier, and **`gated` measured at
   0.67 precision and deliberately excluded from the hard gate** because a false
   "gated" would downgrade a genuinely dangerous tool. **Not wired into CI** —
   unlike the deterministic precision gate, calibration is run by hand.

### What this document says to do next

In priority order, given recall 0.200 and 2 of ~9 checks:

1. **Recall, not breadth.** The three named gaps in `docs/roadmap.md`, plus the
   agent-graph entry-point gap found in PR #17. Breadth on a detector that finds
   a fifth of what it claims is the roadmap's own named trap.
2. **Policy file loading** (§5) — small, and it is what makes the tier *the
   customer's* conscience rather than ours.
3. **Calibration into CI** — the deterministic gate is a headline guarantee; the
   judged tier's is run by hand. Add a case per check and gate it.
4. **Then** checks 3–5, each with labelled cases before it ships.
