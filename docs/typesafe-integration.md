# TypeSafe integration: Palisade as an AI Safety Engineer

> Status: evolving from "linter" → **the AI Safety Engineer you hire**. Shipped:
> - **SEE (static)** — `palisade-sec map`: OFFLINE inventory of the AI surface.
> - **JUDGE (static)** — `palisade-sec audit`: excessive-agency check via TypeSafe.
> - **PROBE (active)** — `palisade-sec redteam`: Map-driven adversarial attack
>   suite; advisory/offline to synthesize, gated to execute.
>
> Scope owner: this document is the spec; code lands under `src/palisade_sec/semantic/`.

## The bigger arc: the hire, not the tool

Positioned like an "AI CMO" or "AI PM" agent, Palisade is the **AI Safety
Engineer/Officer** a company plugs in. The reference job description (see
`docs/ai-safety-engineer-role.md` if captured) *is* the product spec. A real
safety engineer has three senses; a linter has one:

| Sense | What | When | Status |
| --- | --- | --- | --- |
| **Static** | read code → map + checks | pre-commit / CI | ✅ map, audit |
| **Active** | *run* the system with adversarial inputs | pre-ship | 🚧 redteam (synth done; exec gated) |
| **Runtime** | *watch* production, trace incidents | in-prod | ⬜ opt-in, self-hosted SDK |

The senses form the loop that makes it an engineer, not a scanner: **SEE** →
**PROBE** (red-team/evals) → **GUARD** (generate guardrails) → **WATCH**
(runtime) → incident → new static check + regression test → back to SEE.

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

| # | Verb | Meaning | Status |
| --- | --- | --- | --- |
| 1 | **SEE** | inventory every place AI is used | ✅ `map` (offline) |
| 2 | **JUDGE** | assess every failure mode | 🚧 1 of ~9 checks + 5 taint rules |
| 3 | **DECIDE** | rank by risk, apply *your* policy | 🚧 policy scaffold |
| 4 | **FIX** | propose guardrail + test | ✅ taint (`fix`); ⬜ semantic |
| 5 | **ENFORCE** | CI gate, baseline, posture report | 🚧 `audit --ci`; ⬜ posture/`review` |
| 6 | **PROVE** | calibrated, grounded, not hallucinated | ✅ grounded PROBE; ⬜ per-check calibration |

**Complete v1 target:** `map` (done) + ~5 checks + one `review` report merging
taint + semantic with a posture score + per-check calibration.

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
  the wedge and the trust. Do not touch its contract.
- The semantic layer is a **separate tier**: a new `audit` subcommand, behind a
  new optional extra `palisade-sec[semantic]`, that is loud about what leaves the
  machine and reads the key from the environment only.
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

```
src/palisade_sec/semantic/
├── __init__.py
├── probe.py     # deterministic: IR → safety artifacts (Artifact, harvest_*)
├── policy.py    # pydantic: editable criteria + thresholds ("your company")
├── judge.py     # TypeSafe client wrapper; Judge protocol; graceful degradation
└── audit.py     # orchestrate: harvest → judge → decide → SemanticFinding
```

`scanner.py` gains one small refactor: the file-discovery + lowering loop is
extracted into `lower_project(...)` so both `run_scan` and the semantic path get
IR modules from the same code (no duplication, no behavior change to `scan`).

## 4. The check catalog (grows over time)

Each check reuses IR artifacts the PROBE already has and maps to a TypeSafe
primitive and a real failure class (OWASP LLM Top-10 / MITRE ATLAS).

| Check | IR artifact → `state` | Primitive | Judgment |
|---|---|---|---|
| **Excessive agency** (LLM08) — *shipping first* | tool `FuncDef` + capabilities found in body | Noul + Score | Can this tool take an irreversible/destructive action with no confirmation? |
| Sanitizer really neutralizes (LLM01) | sanitizer body + sink kind + trace | Noul + Score | Does this body neutralize injection for this sink? (Vanna case) |
| Hidden LLM call sites (recall) | model-shaped `Call` nodes | Noul | Is this an LLM invocation? (`chain.run`, custom wrappers) |
| Unresolved dynamic dispatch (recall) | ambiguous method + hierarchy | Noul | Does this forward untrusted input to a model/sink? |
| Insecure output handling (LLM02) | LLM-tainted value → non-exec sink | Noul | Is model output trusted downstream without validation? |
| Secrets/PII in prompts (LLM06) | prompt `StrJoin` templates | Noul + Score | Does this prompt embed credentials/PII or leak the system prompt? |
| Unsafe framework defaults | `Call` kwargs (`allow_dangerous_code=True`) | Noul | Is this an unsafe default in context? |
| Missing human-in-the-loop | high-harm sink w/o confirmation gate | Noul | Should this require human approval before executing? |

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

## 7. First slice: excessive-agency check

Ships in this PR. End-to-end proof of the new spine, chosen because it needs
**zero taint** — it validates the PROBE → JUDGE → DECISION path on its own.

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
'palisade-sec[semantic]'` and `TYPESAFE_API_KEY`.

## 8. Sequence after this slice

1. Sanitizer semantic verifier (upgrades the existing MED "unverified sanitizer"
   tier; hits the Vanna CVE story).
2. Policy engine file loading + `[tool.palisade.semantic]` config.
3. Corpus eval harness for the semantic tier (precision/recall per check), wired
   into CI like the core gate.
