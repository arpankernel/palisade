# Roadmap: production progression, Phases 0–6

How Palisade goes from a working v0.4.x to applied agentic-safety
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
| `redteam` synthesis + gated execution + scoring, on a pinned corpus | **Evals** - a grounded, calibrated harness for a verifiable failure class |
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
  run -> handoff -> a dangerous-capability agent). Calibrated on labelled fixtures
  and gated in CI.
- Red-team **synthesis and gated execution** - a Map-driven adversarial attack
  suite (advisory, offline) that can be fired at a user-provided target with
  `--approve`, scored by the judgment backend.

**Upcoming (no dates; sequenced after the checks are calibrated on the corpus):**

- Guardrail generation - installable guardrail middleware plus a regression test
  per confirmed finding.
- Calibration of the **judgment** signals (exploitability, agency, posture) on a
  real labelled corpus; until then those signals are labelled uncalibrated, while
  the deterministic detections (taint rules and `PI-AGENT-HANDOFF`) carry a
  measured, CI-gated precision.
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

## Where we are (v0.4.0-dev)

**Phase 0 is complete.** The engine, five rules, both frontends, library
mode, the baseline/CI flow and a template-based `fix` are shipped and
published, pinned by 185 tests. Quality is now measured rather than
asserted, against a pinned benchmark corpus of 26 third-party repos
(17,343 files Palisade actually scans):

| Metric | Value |
|---|---|
| Precision | **1.000** (tp=2, fp=0) |
| Recall | **0.667** (tp=2, fn=1) |
| F1 | **0.800** |

Zero false positives across 17,343 files of real third-party code. The one
miss is PandasAI's CVE-2024-12366, whose exec sits behind dynamically
dispatched pipeline steps that bounded static taint cannot follow. It is
labelled as a miss on purpose rather than deleted, so recall stays honest
and the gap stays visible. Full detail in [proof-scans.md](proof-scans.md).

| Phase | Theme | Status |
|---|---|---|
| 0 | Measure | **Done.** P/R published and gated in CI; corpus pinned with recorded SHAs; FP regression harness live; inline suppressions shipped; self-security enforced over an adversarial corpus |
| 1 | Distribute | **Next up** - SARIF, GitHub Action, pre-commit; the public-launch gate lives here |
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
  byproduct; the regression gate is the point. *(Done: scores both the fast
  fixture corpus on every push and the pinned 26-repo third-party corpus
  weekly. The harness now also fails when it measures nothing, after an
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

- **SARIF output** - the single highest-leverage feature; the standard
  interface every AppSec pipeline speaks.
- **GitHub Code Scanning integration** - SARIF upload → findings in the
  Security tab and as inline PR annotations, zero glue.
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
premature (current baseline: ~1,600 files in ~36 s).

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
