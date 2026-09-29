# Palisade — Product Requirements Document

> **One line:** Palisade is the **AI Safety Engineer you hire** — a pluggable agent
> that continuously finds, tests, and helps fix the ways your AI systems can be
> made to misbehave, and turns safety from a review step into infrastructure.

- **Status:** v0.5.2 shipped, live on PyPI as `palisade-sec`. The offline static
  core, the judgment layer (`audit`/`review` + posture), red-team synthesis and
  gated execution, multi-agent handoff detection, SARIF + CWE/OWASP-2025 mapping,
  a GitHub Action and pre-commit hook, and SBOM/provenance are all shipped. The
  guardrail/safety-case generators and the runtime tier are the remaining v1/v3
  gaps.
- **Owner:** Arpan (founder). **Companion specs:** `typesafe-integration.md`
  (technical design), `ai-safety-engineer-role.md` (the role this product fills),
  `roadmap.md` (phase status), `judgment-layer.md` (the bring-your-own-endpoint setup).
- **Last updated:** 2026-09-29.

---

## 1. Problem

Companies are shipping AI agents that *take actions* — run code, query databases,
send messages, spend money. The AI decides when to use these powers, and a
motivated user can manipulate that decision (prompt injection, jailbreaks,
tool coercion). This is OWASP LLM Top-10 #1 and behind real, exploited CVEs
(Langflow CVE-2025-3248 on CISA KEV, PandasAI CVE-2024-12366, Vanna
CVE-2024-5565).

Today, defending this is either:
- **Runtime proxies / guardrail SaaS** — paid, in the traffic path, bolted on late,
  and you have to know to wire them in; or
- **A human safety engineer** — scarce, expensive, and reviews manually.

Nobody offers the thing a company actually needs: **a safety engineer's whole
job, as software** — sees the AI surface, tests it adversarially, proposes the
guardrails, watches production, and produces the evidence that it's safe to ship.

## 2. Vision

Position Palisade alongside emerging role-agents ("AI CMO", "AI PM"): **the AI
Safety Officer/Engineer any company can plug in.** It owns your AI safety posture
continuously, across all your codebases and running systems — advisory by
default, with human approval gates on anything it changes.

The reference AI Safety Engineer job description (`ai-safety-engineer-role.md`)
is treated as the product spec.

## 3. Users & buyer

| Persona | Need | How they use Palisade |
| --- | --- | --- |
| **App/agent developer** | Don't ship an exploitable agent | `scan`/`map`/`redteam` in dev + CI |
| **Security / AppSec engineer** | Coverage of the LLM attack class they can't audit by hand | `audit`, red-team evidence, safety cases |
| **Eng leadership / buyer** | Evidence a system is safe to deploy; a posture they can track | posture report, safety case, CI gate |
| **AI platform team** | Guardrails + monitoring as reusable infra | guardrail SDK, runtime monitoring |

Primary wedge user: the developer (offline core). The team that activates the
judgment layer (an endpoint in `.env`): security/eng leadership. All of it is
free and MIT; activation means bringing an endpoint, not buying a tier.

## 4. Product principles (non-negotiable)

1. **Free static core stays free, offline, and keyless.** `scan` + `map` make no
   network calls, need no account, and never leave the machine. This is the trust
   and the adoption wedge. Never dilute it.
2. **Grounded, never hallucinated.** Every judgment is tied to a fact the static
   analyzer verified (a real dataflow, a real tool, a real call site). No
   raw-file "ask an LLM what's wrong."
3. **Advisory + approval gates.** Palisade proposes attacks, guardrails, and
   fixes; a human approves any mutating or production action. Enforced in code.
   A safety product must model safe autonomy.
4. **Never executes the customer's codebase.** Static analysis parses only.
   Dynamic testing drives a target the *user* provides, in their environment.
5. **Runtime is opt-in and self-hostable.** Being in the production path is a
   choice the customer makes, run on their infra — not a mandatory SaaS proxy.
6. **Measured, not asserted.** Every detection tier is calibrated on a labelled
   corpus with a published precision/recall and a CI gate.

## 5. What the product does — the three senses

A linter has one sense. A safety engineer has three, and they form a loop:

```
   SEE (map the AI surface, statically)
        │
        ▼
   PROBE (red-team + evals: run it under adversarial pressure)
        │  failures →
        ▼
   GUARD (generate guardrails + safety case)
        │  deployed →
        ▼
   WATCH (runtime monitoring, incident detection)
        │  incident → RCA → new static check + regression test
        └──────────────────────► back to SEE
```

Mapped to the six things a safety engineer does:

| Verb | Capability | Sense | Status |
| --- | --- | --- | --- |
| **SEE** | AI System Map: LLM calls, prompts, tools, agents, retrieval, dangerous flags | static | ✅ `map` (incl. multi-agent graph: OpenAI Agents SDK, LangGraph, CrewAI) |
| **JUDGE** | Semantic checks + 5 taint rules + the deterministic `PI-AGENT-HANDOFF` finding | static | ✅ 2 semantic (excessive agency, taint exploitability) + 5 taint + agent-handoff; ⬜ fake-sanitizer/secrets-in-prompt/unsafe-defaults/insecure-output |
| **PROBE** | Map-driven red-team + behavioral evals (jailbreak, tool-use safety) | active | ✅ synthesis + gated execution (`--execute`/`--approve`, `HttpTarget`, judge-backed scorer) |
| **DECIDE** | Unified risk model (`likelihood × impact`) + editable per-org policy | static+active | ✅ risk model + posture; 🚧 per-org policy profiles |
| **GUARD/FIX** | Guardrail generator, safety-case generator, remediation + regression tests | active+runtime | ✅ deterministic taint `fix`; ⬜ guardrail + safety-case generators |
| **ENFORCE** | CI gate, baseline, posture report, PR comments, SARIF, GitHub Action, pre-commit | all | ✅ gates + posture + SARIF (CWE/OWASP-2025 tags) + Action + pre-commit; ⬜ PR-comment agent |
| **WATCH** | Opt-in self-hosted runtime SDK: monitoring, circuit-breaking, incident capture | runtime | ⬜ |
| **PROVE** | Per-check calibration on the benchmark corpus, adversarial verification | all | ✅ core precision 1.000, CI-gated; 🟡 judged layer on a seed corpus (full-benchmark calibration pending) |

## 6. Where TypeSafe fits

The static core is deterministic and needs no model. The **judgment** layer uses
[TypeSafe](https://docs.typesafe.ai) System One as the *measurement instrument*:
calibrated typed answers (Noul = P(true), Score = severity, Choice = category)
instead of parseable prose. It scores "is this sanitizer real?", "did this attack
land?", "is this output harmful?" — and, at runtime, can serve as the live I/O
filter. The judgment layer needs an endpoint + key (`TYPESAFE_API_KEY` or a
generic `PALISADE_JUDGE_API_KEY`); the offline core never calls it.

## 7. Packaging

Everything is MIT and free to run. There is no paid tier. The only distinction
is **keyless-and-offline** versus **bring-your-own-endpoint** — the user decides
whether to plug in a judgment endpoint (their key, their choice of provider).

| Layer | Surface | Network | Key |
| --- | --- | --- | --- |
| **Offline core** | `scan`, `map`, `baseline`, `fix` (deterministic), advisory `redteam` synthesis, SARIF, GitHub Action, pre-commit | none | none |
| **Judgment layer** | `audit`, `review` + posture, red-team execution (`--execute`); (upcoming) guardrail/safety-case generation | your endpoint | your key (`.env`) |
| **Runtime (upcoming)** | Self-hosted monitoring / guardrail SDK, incident loop | user's infra | user's config |

Adoption path: developer installs the free linter → team configures an endpoint
in `.env` to turn on judgment + review → platform team self-hosts runtime. No
step is gated behind a purchase; the gate is only "do you want to bring an
endpoint."

## 8. Scope & roadmap

### v1 — "Complete AI Safety Engineer" (mostly shipped)
Credibly does the whole job, pre-production.
- **SEE:** `map`, incl. the multi-agent graph ✅
- **JUDGE:** excessive agency ✅, taint exploitability ✅, deterministic
  `PI-AGENT-HANDOFF` ✅ + fake-sanitizer, secrets-in-prompt, unsafe-defaults,
  insecure-output (as declarative data) ⬜
- **PROBE:** `redteam` synthesis ✅ + execution adapters (`HttpTarget`) + live
  judge-backed scorer ✅
- **DECIDE + ENFORCE:** `palisade review` = one prioritized report merging taint +
  semantic + red-team, with a posture score ✅; SARIF + CWE/OWASP-2025 + Action +
  pre-commit ✅
- **GUARD:** guardrail generator for the top findings + safety-case draft ⬜
  (the last open v1 gap)
- **PROVE:** core precision 1.000 CI-gated ✅; per-check calibration of the judged
  layer on the full 26-repo corpus 🟡 (seed corpus done, full benchmark pending)

**v1 exit criteria:** on a real target agent, Palisade produces (1) a full AI
System Map ✅, (2) a red-team run with landed/blocked evidence ✅, (3) generated
guardrails + tests ⬜, (4) a safety case ⬜, (5) a CI gate ✅ — with published
precision per check 🟡. Remaining to close v1: the guardrail + safety-case
generators and full-benchmark per-check calibration.

### v2 — Depth & distribution
SARIF + GitHub code-scanning ✅, GitHub Action + pre-commit ✅, supply-chain
(pinned actions, SBOM, provenance) ✅. Remaining: the full 9-check library,
PR-comment agent, org policy profiles (fintech/healthcare/default), LLM-assisted
`fix --apply`, notebook (`.ipynb`) support, deeper multi-agent recall, more
framework coverage.

### v3 — Runtime & the agent
Opt-in self-hosted runtime SDK (monitoring, circuit-breaking, incident capture);
the agent orchestration layer — planner + memory of posture over time + proactive
re-audit on every PR. This is the full "hired officer" experience.

## 9. Functional requirements (per capability)

**SEE / `map`** — Inventory every LLM call (provider, model), prompt (static vs
dynamic), tool (with capabilities), agent/chain, retrieval site, and dangerous
config flag. Offline, deterministic, terminal + JSON. *Done.*

**JUDGE / `audit`** — Run semantic checks over Map artifacts; each check =
{artifact, batched questions, decision policy}. Route pass/review/block. Adding a
check is data, not engine code. Requires an endpoint; explicit about egress.
*Excessive agency + taint exploitability done; the further check library is next.*

**PROBE / `redteam`** — Synthesize a targeted attack suite from the Map
(advisory, offline). Execute against a user-provided `Target` only with
`--approve`; score landed attacks (deterministic tool-invocation + judge-backed
scorer); emit an evidence report. *Synthesis + gated execution done.*

**DECIDE / policy** — Unified `risk = likelihood × impact` across static + active
findings, surfaced as the `review` posture score. *Risk model + posture done;
per-org policy profiles (`.palisade/policy.yaml`) next.*

**GUARD** — For each confirmed risk, generate an installable guardrail (allowlist
wrapper, confirmation gate, output validator, host allowlist) + a regression
test. Assemble a **safety case**: system description (Map) + tests (evals) +
red-team results + guardrails + residual risks. *Deterministic taint `fix`
done; the guardrail + safety-case generators are the main open v1 work.*

**ENFORCE** — `--ci` gates on new high-severity findings only (baseline-diffed);
`palisade review` prints/exports one posture report; SARIF (with CWE/OWASP-2025
tags and `security-severity`), a GitHub Action, and a pre-commit hook. *Done;
the PR-comment agent is next.*

**WATCH (v3)** — Self-hosted SDK wraps LLM/tool calls: policy filtering,
circuit-breaking on runaway/high-cost loops, anomaly flags, incident traces that
feed back into new static checks.

**PROVE** — Every detection tier scored on `corpus/` (pinned repos) with
published precision/recall and a CI precision gate; adversarial multi-vote
verification before a BLOCK.

## 10. Non-functional requirements

- **Trust/privacy:** the offline core sends nothing off-machine; the judgment
  layer sends only IR-verified snippets; runtime self-hosted; API keys env-only,
  never logged.
- **Safety of the tool itself:** never executes/imports scanned code (live test);
  approval gates on all mutating/prod actions.
- **Performance:** static scan of ~1,500 mixed files in ~40s; red-team synthesis
  offline and instant; judgment batched (one call per artifact).
- **Reliability:** a hostile file never crashes a scan (resource caps, parse-fail
  skip); invalid config/rules degrade to warnings.
- **Extensibility:** new language = a frontend (proven: JS/TS added with zero
  engine change); new check = declarative data; new framework = a rule/pattern PR.

## 11. Success metrics

Tied to the JD's "what success looks like":
- **Coverage:** % of a repo's AI surface mapped; # frameworks supported.
- **Catch rate:** unsafe behaviors caught pre-ship (red-team landed → fixed).
- **Evidence:** every deploy decision backed by a Map + red-team run + safety case.
- **Precision:** published per-check precision ≥ target on the corpus; core stays
  1.000.
- **Adoption:** installs → teams that activate a judgment endpoint; findings
  fixed vs. suppressed.
- **MTTR (v3):** time from a runtime incident to a shipped regression test.

## 12. Risks & mitigations

| Risk | Mitigation |
| --- | --- |
| Going dynamic erodes the "offline/no-key" trust | Offline core untouched; judgment/runtime clearly separate + self-hostable |
| Executing customer agents is dangerous | Never execute their code; user provides the target + keys; gated by approval |
| Semantic tier hallucinates / loses precision | Grounding in verified IR facts; per-check calibration + CI gate; adversarial verify before BLOCK |
| The safety agent itself acts unsafely | Advisory + approval gates enforced in code; no auto-prod changes |
| Scope creep into alignment research | Stay "infrastructure that operationalizes safety," per the JD |
| TypeSafe dependency / cost | The offline core never calls it; batched calls; deterministic scoring where possible |

## 13. Open decisions

Resolved since the first draft: `review` + posture, red-team execution + scorer,
SARIF/Action/pre-commit, and multi-agent handoff detection all shipped (0.5.x).
Remaining open:

- Last v1 gap ordering: the **guardrail generator** vs the **safety-case
  generator** vs the **further static JUDGE check library** (fake-sanitizer,
  secrets-in-prompt, unsafe-defaults, insecure-output) — which first?
- Calibration: grow the judgment corpus from the seed set to real repos and
  publish full-benchmark per-check precision (the `gated` signal is known-weak).
- Guardrail generation: deterministic templates first, LLM-assisted later — order?
- Runtime SDK language for the infra layer (JD suggests Go/Rust) — defer to v3.
- Near-term in-flight PRs to fold in: notebook (`.ipynb`) support, deeper
  multi-agent recall (container entry points + conditional edges), and gate/FP
  hardening.

## 14. Out of scope (for now)

Doing alignment research; hosting/executing customer agents on our infra; being
an inline runtime proxy (we ship a self-hosted SDK instead); non-LLM appsec
(that's Bandit/Semgrep's job — Palisade is the LLM-dataflow-aware layer).
