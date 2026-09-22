---
title: "Roadmap"
description: "Phases 0–6, Measure → Remediate, with the sequencing thesis and status."
---

How Palisade goes from a working v0.5.x to applied agentic-safety
infrastructure a team puts in front of every PR. This sequences the work and
argues **why this order** - then reports current status honestly against it.

## v1: the agentic-safety layer

Alongside the phase progression below, Palisade is growing from a taint linter
into applied agentic-safety infrastructure: it exercises, in miniature and at
the application layer, the disciplines the long-horizon catastrophic-risk agenda
runs on. Each existing capability maps onto a pillar of that agenda:

| Palisade capability | Agenda pillar it instantiates |
|---|---|
| `scan` / `map` - the action-boundary surface (input → model → exec/shell/SQL/payments/secrets) | **Agentic safety** - the model→high-impact-action interface, which is the loss-of-control surface as autonomy scales |
| `redteam` synthesis + gated execution + scoring, on a pinned corpus | **Evals** - a grounded harness for a verifiable failure class |
| `review` + posture score, grounded in verified static facts | **Safety cases** - a structured, evidence-backed argument about a system's safety posture |
| advisory + approval gates (proposes all; human approves mutating/prod; never executes customer code) | **Oversight** - a human at the high-impact boundary, machine doing the labor |
| SARIF, CI gates, CWE/OWASP-LLM mapping, disclosure/provenance | **Governance** - makes safety practice enforceable as an org requirement |

The scope is deliberate and honest: this is engineering infrastructure at the
deployment layer, **not frontier alignment research**. Its catastrophic-risk
relevance is anticipatory - the failure it hardens today is the same shape that
scales as agents gain capability and autonomy. It is layered on the
deterministic core, never replacing it. It is all MIT and free; the split is
keyless-and-offline versus bring-your-own-endpoint.

**Shipped:**

- `map` - offline inventory of the AI surface (LLM calls, prompts, tools, agents,
  retrieval, dangerous flags).
- Judgment layer over any OpenAI-compatible endpoint (TypeSafe by default),
  configured in `.env`, behind one `JudgeBackend` interface. An unverified
  backend is best-effort and can never BLOCK or raise a Critical posture on
  judgment alone.
- `audit` - excessive-agency and taint-path exploitability checks, each grounded
  in a verified static fact.
- `review` + **posture score** - one composed, risk-ranked report (a number and
  a band over detected findings).
- **Multi-agent detection** - the agent graph in `map` (agents, tools,
  capabilities, handoffs) across OpenAI Agents SDK, LangGraph, and CrewAI, plus
  the deterministic `PI-AGENT-HANDOFF` finding in `scan` (untrusted input -> agent
  run -> handoff -> a dangerous-capability agent). Measured on labelled fixtures
  and gated in CI.
- Red-team **synthesis and gated execution** - a Map-driven adversarial attack
  suite (advisory, offline) that can be fired at a user-provided target with
  `--approve`, scored by the judgment backend.
- **Judgment calibration harness** (`scripts/calibrate.py` + a labelled corpus).
  Preliminary: measured on a 10-case seed corpus (n=4 to 6 per signal), not a
  benchmark result; the judged layer stays advisory (see
  `corpus/judgment/RESULTS.md`). `gated` is marked known-weak on that seed (the
  model over-predicts gating) - reported, not trusted to downgrade a finding.
- **SARIF output + GitHub code-scanning Action** - `scan --sarif` emits SARIF
  2.1.0 (severity mapped, line-shift-resilient fingerprints); a five-line
  workflow uploads findings to the Security tab, dogfooded on our own `src`.

**Upcoming (no dates):**

- Guardrail generation - installable guardrail middleware plus a regression test
  per confirmed finding.
- Grow the judgment corpus to real repos and calibrate `gated`; the seed gate is
  fixture-scale. The deterministic detections (taint rules, `PI-AGENT-HANDOFF`)
  already carry a measured, CI-gated precision.
- Multi-agent recall: `crew.kickoff` / compiled-LangGraph `.invoke` entry
  mapping, conditional edges, and cross-module agent wiring.

## The ordering thesis

One rule drives the sequence: **at each stage, relieve the single binding
constraint preventing the tool from getting or keeping users.** For a free,
open-source *security* tool, three facts fix the order:

1. **Trust is scarce and asymmetric.** A noisy or crashing scanner gets
   uninstalled and badmouthed once, forever. → Quality must be *measurable*
   before reach.
2. **Adoption is the improvement engine.** Real repos are the test corpus;
   real FP reports are the precision tuning. → Distribute early - but only
   after you won't embarrass yourself.
3. **Coverage gates per-user value; expansion dilutes focus.** Cover the
   beachhead deeply before widening it.

Through-line: **Measure → Distribute → Cover → Scale → Certify → Expand →
Remediate.** Trust before reach before depth.

## Where we are (v0.5.1)

**Phase 0 is complete.** The engine, six rules (five taint rules plus
`PI-AGENT-HANDOFF`), both frontends, library mode, the baseline/CI flow and a
template-based `fix` are shipped and pinned by the test suite. 0.5.0, with the
judgment tier (`audit`, `review`, `redteam --execute`), is on PyPI; 0.5.1 is
the next release. Quality is now measured rather than
asserted, against a pinned benchmark corpus of 26 third-party repos
(17,352 files Palisade actually scans, 0.5.1):

| Metric | Value |
|---|---|
| Precision | **1.000** (tp=2, fp=0) |
| Recall | **0.200** (tp=2, fn=8; 10 hand-verified paths) |
| F1 | **0.333** |

Zero false positives across 17,352 files of real third-party code. Two small
repos (84 files) contain no untrusted input for taint to start from; they are
reported but excluded from the precision claim.

Recall is measured against 10 real paths, each hand-verified at the pinned
commit: the Vanna CVE in two releases (found), PandasAI's CVE-2024-12366
(missed: dynamically dispatched pipeline steps), and 7 paths found by a
2026-09-22 audit of the clean repos (all missed). Of the 8 misses, 4 run in a
sandbox by default (autogen, dspy) and 3 reach raw SQL or a shell directly
(crewai-tools, griptape, the Anthropic SDK's bash tool). Every miss stays
labelled, so recall stays honest and the gaps stay visible. They point at
three engine capabilities, now the top of Phase 2: tool-call arguments as
model output, more LLM call shapes, and method calls on objects the engine
cannot resolve. Full detail in [proof-scans.md](/palisade/docs/proof-scans/).

| Phase | Theme | Status |
|---|---|---|
| 0 | Measure | **Done.** P/R published and gated in CI; corpus pinned with recorded SHAs; FP regression harness live; inline suppressions shipped; self-security enforced over an adversarial corpus |
| 1 | Distribute | **In progress** - SARIF output + a code-scanning GitHub Action shipped (dogfooded on our own src); pre-commit and a Marketplace action remain. The public-launch gate lives here |
| 2 | Cover | Partial - notebooks, framework breadth, rule-test framework for community PRs |
| 3 | Scale | Open - incremental scanning, caching, perf gates |
| 4 | Certify | Started - SECURITY.md and release discipline shipped; signing, SBOM, provenance remain |
| 5 | Expand | **v1 pulled forward** (JS/TS frontend shipped as the architecture proof); the JS benchmark corpus + precision gate remain |
| 6 | Remediate | **v1 pulled forward** (deterministic template `fix`); the LLM-assisted, eval-gated diff engine remains |

Two items originally sequenced late were deliberately pulled forward in v0.3
with reduced scope, noted in their phases below.

## The phases

### Phase 0 - MEASURE

**Constraint:** "We can't tell if the tool is good, and can't change it
without silently breaking it."

- Benchmark corpus: CVE repos pinned at *vulnerable* and *patched* commits
  (PandasAI, Vanna, Langflow, LangChain PAL/LLMMath) + ~25 clean popular
  Python AI repos (the honesty half - guards against overfitting to the CVE
  set). Ground-truth labels per repo: `file:line → rule → should-flag /
  should-be-silent`.
- Precision/Recall/F1 harness in CI that **fails the build if precision
  drops** below threshold (~90% to start). The published number is a
  byproduct; the regression gate is the point. *(Done: every PR is gated on
  the fast fixture corpus, and the pinned 26-repo third-party corpus is scored
  weekly and on demand. The harness now also fails when it measures nothing, after an
  unlabelled run reported precision=1.000 on tp=0 fp=0 fn=0.)*
- FP regression harness: every reported false positive becomes a permanent
  must-stay-silent fixture. *(Already practiced informally - the test suite
  grew exactly this way - needs formalizing against the corpus.)*
- Inline suppressions: `# palisade: ignore[PI-EXEC] - reviewed, sandboxed`,
  tracked and surfaced in reports. *(Done: `#` and `//` forms, on the sink
  line or the one above; suppressed findings are counted, carry their reason
  into `--json`, and a comment that stops matching anything is reported as
  stale. A silent suppression is how a vulnerability quietly returns.)*
- Self-safety guarantees: never-execute and never-crash assertions.
  *(Shipped: `tests/fixtures/hostile/` adversarial corpus driven by a
  `sys.addaudithook` tripwire - no exec/import of target code, no
  subprocess, no sockets; plus resource caps and skip-with-warning
  guarantees. See `HARDENING-AUDIT.md`.)*

**Done when:** published P/R on N repos; precision gate live in CI;
suppressions shipped. **Trap:** overfitting to the four CVE repos.

### Phase 1 - DISTRIBUTE

**Constraint:** "Even people who like it can't get it into their workflow."
Directly serves the North Star metric: repos running Palisade in CI.

- **SARIF output** *(shipped)* - the single highest-leverage feature; the
  standard interface every AppSec pipeline speaks. `scan --sarif` emits SARIF 2.1.0.
- **GitHub Code Scanning integration** *(shipped)* - a five-line workflow uploads
  findings to the Security tab, dogfooded on our own `src`.
- Published GitHub Action (pinned) on the Marketplace; pre-commit hook;
  CI recipes for GitLab/CircleCI/Jenkins/Azure.
- Versioned `--json` schema *(shipped: `schema_version: 1`, documented)*;
  baseline UX polish (`--update-baseline`, stale reporting).

**Done when:** a 5-line workflow puts findings in the GitHub Security tab.
**Trap:** unpinned deps in a security tool's own action.

> **▶ PUBLIC LAUNCH GATE (fires once, here).** Only now do you have a
> precision number *and* copy-paste CI integration. Spend the one-time
> Show HN / Reddit attention spike here - not before. During Phases 0–1,
> run a private ~5-repo design-partner beta to harvest real FP data.

### Phase 2 - COVER

**Constraint:** "It doesn't understand *my* framework / file type / Python
version." Post-launch churn comes from coverage gaps; this phase also opens
the community-rule flywheel - the moat.

**First, the measured recall gaps** (recall is 0.200 on 10 hand-verified
paths; each item below explains several of the 8 labelled misses):

- **Tool-call arguments as model output.** Arguments to a registered agent
  tool (`BaseTool._run`, autogen `BaseTool.run`, griptape activities,
  decorator-registered tools) are written by the model; treat them as tainted.
- **More LLM call shapes.** `model_client.create`/`create_stream`, dspy
  Module calls and `dspy.Predict`/`ChainOfThought`, `prompt_driver.run`,
  `messages.stream`.
- **Method calls on objects.** Resolve `obj.method(x)` and
  `self.attr.method(x)` through constructor and attribute types (abstract
  executors, SQL drivers), and model code-execution sinks reached that way
  (`execute_code_blocks`, `interpreter.execute`, writes to a shell's stdin).

- Python syntax matrix (3.11–3.13+: `match`, walrus, type-params) in CI.
- **Jupyter notebook support** (`.ipynb` cells → IR) - a large share of AI
  code lives in notebooks.
- Framework-rule breadth, pure data: Django ORM/raw, SQLAlchemy `text()`,
  Starlette; LangGraph, CrewAI, AutoGen, LlamaIndex, Haystack, DSPy;
  template sinks; Bedrock/Vertex/Groq providers.
- Robustness fuzz against the top ~1000 PyPI AI repos.
- **Rule-test framework** (pulled forward from "ecosystem"): community rule
  PRs cannot land without must-flag + must-be-silent fixtures and a green
  precision gate. This is what makes community contribution safe.

**Done when:** matrix green, notebooks scanned, first external rule PRs
merged. **Trap:** coverage sprawl buying recall with false positives.

### Phase 3 - SCALE

**Constraint:** "Too slow or noisy for a large repo / busy CI." Only bites
once Phases 1–2 produce adopters with big repos - optimizing earlier is
premature (current baseline: 1,576 files of Langflow in ~9 s on an Apple M3
Pro).

- Incremental / diff-aware scanning (changed files + their taint
  neighborhood) - correctness tested against full scans.
- Content-hash caching; parallel processing with deterministic output.
- Per-file timeouts + global budget; honest truncation reporting *(partially
  shipped: truncation notes exist)*.
- Published perf benchmark on a 500k+ LOC repo with a regression gate.
- Rules-ecosystem maturity: versioned rule packs, rule-severity SemVer,
  deprecation policy.

### Phase 4 - CERTIFY

**Constraint:** "Serious security orgs won't run an unsigned, opaque tool."

- Sigstore-signed releases, SLSA provenance, CycloneDX SBOM, reproducible
  builds, minimal-dependency audit.
- `SECURITY.md` + coordinated disclosure (you *will* receive vuln reports).
  *(Shipped.)*
- Telemetry: **off by default or not at all** - source never leaves the
  machine. Default-on telemetry is self-sabotage for a security tool.
- Release discipline: SemVer, changelog *(shipped)*, deprecation/LTS policy.
- Optional compliance mapping: CWE + OWASP LLM Top-10 tags per rule.

### Phase 5 - EXPAND *(v1 pulled forward - deliberately, with scope control)*

Original sequencing put JS/TS after the Python wedge was won, and that logic
stands for *investment*. What shipped early in v0.3 is the **architecture
proof**: a tree-sitter JS/TS frontend emitting the same IR with zero engine
changes, Express/Node sources and sinks, behind an optional `[js]` extra so
the core stays lean. Remaining Phase 5 work before JS findings deserve equal
trust:

- JS benchmark corpus + its own precision gate (mirror Phase 0).
- JS/TS rule-pack depth: Next.js request surfaces, `innerHTML` /
  `dangerouslySetInnerHTML`, Vercel AI SDK, LangChain.js.
- `npx` distribution wrapper for first-class JS DX.

**Reorder trigger honored:** the frontend exists; deeper JS investment waits
for JS demand or JS-side CVEs.

### Phase 6 - REMEDIATE *(v1 pulled forward - the safe subset only)*

The original vision - and correctly sequenced last for its risky half.
What shipped early is the **deterministic, offline** subset:
`palisade-sec fix` emits templated guardrails (allowlist / argv /
SELECT-validator / SSRF-guard) each paired with a regression pytest, and
never touches code. The deferred half remains deferred until the scanner's
trust base (Phases 0–1) is formal:

- LLM-assisted diffs on the **user's own model key**, provider-agnostic.
- **Eval-gated patches**: generate the guardrail diff *and* the pytest, run
  in a sandbox, propose the diff only if the test passes.
- Human-review-first: PR-style diffs, never auto-apply.
- Success metric: accept/merge rate on real findings.

## Dependency graph

```
Phase 0 (Measure) ──▶ Phase 1 (Distribute) ──▶ [PUBLIC LAUNCH]
      │                      ├──▶ Phase 2 (Cover) ┐  interleave, driven by
      │                      ├──▶ Phase 3 (Scale) ┘  what real users hit
      │                      └──▶ Phase 4 (Certify) - pull forward if an
      │                                              enterprise partner appears
      └── correctness guarantees live HERE, not in Phase 4

Phase 5 (Expand) / Phase 6 (Remediate): v1s shipped as proofs; their
deep halves stay gated on Python adoption being real (metrics, not calendar).
```

**Reorder triggers:** enterprise partner → pull Phase 4 signing forward;
JS-side CVE wave → deepen Phase 5; any in-the-wild crasher or FP class →
jumps the queue into Phase 0's harness immediately.

## Sequencing traps (explicit anti-goals)

- Building the LLM `fix` engine before a formally measured scanner.
- Public launch before SARIF + a precision number - wastes the one-time
  attention spike.
- Buying recall with false positives - always net-negative for a security
  tool.
- Default-on telemetry - instantly off-brand.
- Premature performance work before big-repo users exist.

## Metrics ladder

| Phase | Primary metric |
|---|---|
| 0 Measure | Published precision/recall; regression gate live |
| 1 Distribute | **# repos running Palisade in CI (North Star)** |
| 2 Cover | # frameworks covered; # external rule PRs merged |
| 3 Scale | Scan time on 500k LOC; % PRs on incremental mode |
| 4 Certify | Signed-release adoption; enterprise evals reaching pilot |
| 5 Expand | JS precision gate green; # JS/TS repos scanned |
| 6 Remediate | `fix` accept/merge rate on real findings |
