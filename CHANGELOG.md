# Changelog

## Unreleased

Work toward the pre-production AI safety engineer. The deterministic core
(`scan`, `map`, `baseline`, `fix`) stays offline and keyless. A new judgment
layer is bring-your-own-endpoint: it reads an endpoint and key from `.env` and
is used only by `audit` (and, later, `review`).

### Added

- **SARIF output + code-scanning Action.** `scan --sarif` emits SARIF 2.1.0
  (severity high->error/med->warning/low->note; sink as the primary location,
  source and LLM boundary as related locations; line-shift-resilient
  fingerprints). A five-line GitHub Action (`.github/workflows/code-scanning.yml`,
  which also dogfoods on Palisade's own `src`) puts findings in the Security tab.
  This is the Phase-1 distribution wedge - findings where AppSec pipelines already
  look, in a copy-paste workflow.
- **Multi-agent graph (`map`).** `map` now extracts the agent topology: nodes are
  agents (with the tools they hold and the capabilities those tools exercise),
  edges are handoffs (`handoffs=[...]`). It shows which entry agents can reach a
  dangerous capability across a handoff, and adds an `agent_graph` block to
  `--json`. Deterministic and offline. Framework adapters: the explicit-kwarg
  (OpenAI Agents SDK-style `Agent(tools=, handoffs=)`), **LangGraph**
  (`add_node`/`add_edge`, a node's capabilities read from its function body), and
  **CrewAI** (`Crew(agents=, process=)` - sequential chains the agents,
  hierarchical connects the first to the rest).
- **Judgment-layer calibration harness (`scripts/calibrate.py`).** Measures how
  well a JudgeBackend agrees with ground truth on a labelled corpus
  (`corpus/judgment/cases.yaml`): per-question precision / recall / accuracy plus
  a Brier score for the yes/no signals, and exact-tier accuracy + MAE for the
  severity/harm scores. Exits non-zero below the corpus thresholds, so judged
  quality can only ratchet up. This is what turns the exploitability / agency /
  posture signals from "uncalibrated" into measured; the scoring is pure and
  tested offline, and a real keyed run publishes the numbers.
- **Multi-agent calibration.** Labeled fixtures under `corpus/fixtures/agents/`
  (must-flag handoff paths + must-stay-silent safe wirings) join the precision
  corpus, so `PI-AGENT-HANDOFF` is measured (precision/recall) and gated in CI -
  and now in the test suite too (`test_precision_gate.py`). Fixed a real bug the
  fixtures caught: the analysis merged same-named agents across files; it now
  scopes agents per module so findings are attributed to the right file.
- **Red-team execution (`redteam --execute`).** The advisory synthesis can now
  be fired at a live target you own, gated by `--approve` plus a `--target` URL
  (or `PALISADE_REDTEAM_TARGET`). `HttpTarget` POSTs each attack and reads the
  output/tool-calls across common response shapes; a judge-backed scorer decides
  whether each attack landed (deterministic tool-invocation checks plus a
  JudgeBackend for behavioral judgment). `--execute --ci` exits non-zero if any
  attack lands. Palisade never executes your code; it drives the endpoint you
  provide, in your environment. Synthesis stays offline and dependency-free.
- **`PI-AGENT-HANDOFF` finding (`scan`).** A multi-agent prompt-injection path:
  untrusted input runs an agent that can hand off (>=1 hop) to an agent holding a
  dangerous-capability tool. Deterministic, offline, and precision-first - it
  fires only on a complete untrusted -> run -> handoff -> dangerous path, so a
  constant input, a handoff to only-safe agents, or a standalone dangerous agent
  stays silent. Flows through `--json`, `--ci`, and the baseline like any finding.
  v1 tracks untrustedness intra-procedurally (source at the run site or a
  variable assigned from one in the same function).
- **Judgment backends (`palisade_sec.judge`).** One `JudgeBackend` interface
  with two adapters, selected in `.env`: **TypeSafe** (default, calibrated
  typed answers, `verified=True`) and a **generic OpenAI-compatible** endpoint
  (strict-JSON prompt validated against a schema, labelled best-effort and
  `verified=False`). Batched: one call per artifact. Keys are read from the
  environment only and never logged. See `.env.example`.
- **`[judge]` extra** (`httpx`, `python-dotenv`); `[semantic]` kept as an alias.
- **Taint-path exploitability check.** Grounded in a verified `source -> LLM ->
  sink` dataflow, it asks the backend to judge exploitability and impact of that
  specific path. Uncalibrated until scored on the corpus. A verified backend
  refines a finding up or down; an unverified backend is advisory only and never
  moves the deterministic risk.
- **`palisade-sec review`.** One prioritized report composing scan + map + the
  semantic checks + red-team synthesis, with a **posture score** (0-100 plus a
  named band: Critical / High / Moderate / Low). The score is derived from the
  tier counts and printed with the breakdown beside it; it is a posture over
  *detected* findings (`likelihood x impact`), not a safety score. When the
  judgment layer ran, the report says so and marks it uncalibrated; an unverified
  backend cannot manufacture a Critical posture. Terminal, `--json`, `--report`
  (markdown). `--ci` gates only on new HIGH taint findings (baseline-diffed);
  judged signals never gate.
- **`audit` now runs both checks** (excessive agency over tools, exploitability
  over taint paths), so it produces findings on apps that expose no agent tools.
- **`review` judges once per run.** It performs a single judgment pass and emits
  both the composed posture and the audit view (`audit_findings` in `--json`)
  from it, so `audit` and `review` never disagree within a run and a run makes
  half the endpoint calls. Judged output is deterministic within a run but not
  across runs, because the model is probabilistic; the posture score is not
  claimed to be stable run-to-run.

### Changed

- `audit` now reads its backend from `.env` (`PALISADE_JUDGE_BACKEND`,
  `PALISADE_JUDGE_ENDPOINT`, `PALISADE_JUDGE_MODEL`, key vars) instead of the
  TypeSafe SDK, so any OpenAI-compatible endpoint works. An unverified backend
  can never emit a BLOCK on judgment alone; such a decision downgrades to
  REVIEW. The judgment layer is uncalibrated until scored on the corpus.

## 0.4.0 - 2026-09-16

Phase 0 of the roadmap is complete: quality is now measured against a pinned
benchmark corpus instead of asserted. Precision **1.000**, recall **0.667**,
F1 **0.800** across 26 third-party repos and 17,343 scanned files, with zero
false positives. The single miss (PandasAI CVE-2024-12366, whose exec sits
behind dynamically dispatched pipeline steps) is labelled as a miss on
purpose, so recall stays honest and the gap stays visible.

### Added

- **Inline suppressions.** `# palisade: ignore[PI-EXEC] - reason`, on the
  sink line or the one above, with `#` and `//` so Python and JS/TS share
  one syntax. Deliberately loud: suppressed findings are counted, carry
  their reason into `--json` under `suppressions`, and a comment that stops
  matching anything is reported as stale. Without this, a single unfixable
  finding disables the whole scanner.
- **Benchmark corpus.** `corpus/repos.yaml` pins 26 repos with resolved
  SHAs, fetched by `corpus/fetch.py`; `scripts/precision.py` scores both it
  and the fast fixture corpus. A weekly workflow runs the slow one.
- **False-positive regression harness.** `tests/fixtures/regressions/` with
  auto-discovery, so any reported false positive becomes a permanent
  must-stay-silent test and precision only ratchets upward.
- **Releases via Trusted Publishing.** Tag-triggered OIDC publishing with no
  API token anywhere, gated on the full test suite, a tag/version match
  check, an sdist contents check, and a smoke test of the built wheel.

### Changed

- **Findings are deduplicated by sink.** One dangerous line is one thing to
  fix, so it is reported once even when several rules match it or several
  untrusted sources converge on it. The best-evidenced trace is kept and
  collapsed duplicates are recorded in `count`. Previously a library entry
  point with both an `input()` path and a public-parameter path reaching the
  same `exec` produced two identical findings.
- The precision harness scores recall at any severity, since a real
  vulnerability that Palisade deliberately downgrades to MED is still found,
  and scores precision on HIGH only, since advisory rules never gate CI.

### Fixed

- Scanning a file with an invalid escape sequence printed the whole source
  line to stderr, because `ast.parse` raises `SyntaxWarning` and Python
  echoes the offending line. On one real repo that dumped 40 KB of file
  contents and bypassed the 200-char snippet redaction.
- The precision gate reported success on an unlabelled corpus, because
  precision is defined as 1.0 when tp+fp is 0. It now fails when it measures
  nothing.

## 0.3.4 - 2026-09-16

- Packaging fix: the source distribution no longer bundles the documentation
  site. The 0.3.3 sdist accidentally swept in docs-site/node_modules, which
  made it 85 MB across 8,599 files, because hatchling does not honour nested
  .gitignore files. Wheels were never affected, so normal installs were fine.
  The sdist now excludes docs-site, website and .github, and is back to
  roughly 163 KB.


## 0.3.3 - 2026-09-16

- Removed every em dash from the README, docs, website, rule text and code
  comments in favour of plain hyphens, for a cleaner reading tone. This
  release exists so the PyPI project description picks the change up, since
  descriptions are immutable per release.
- Softened the website palette from a vivid crimson (#A31621) to a calmer
  maroon (#6E1F2A). The large fills (page frame, terminal panels, final CTA)
  were harsh to read against the cream canvas.


## 0.3.2 - 2026-09-16

- PyPI listing health: absolute URLs for the README demo image and the
  rules-guide link (relative paths render broken on the PyPI project
  page); package summary now says Python **and JavaScript/TypeScript**.

## 0.3.1 - 2026-09-16

- Terminal output: escape rich markup in notes/warnings/skips so literal
  brackets render verbatim (the `pip install 'palisade-sec[js]'` hint was
  losing its `[js]`). Found by the full-stack verification pass.

## 0.3.0 - 2026-09-16

The "everything deferred" release: multi-language, framework-aware, and
able to propose fixes.

- **JavaScript/TypeScript frontend** (tree-sitter, optional `[js]` extra):
  `.js`/`.mjs`/`.cjs`/`.jsx`/`.ts`/`.tsx` lower into the same taint IR with
  **zero engine changes** - the multi-language architecture, proven. Express
  sources (`req.body`, `req.query`), `eval`/`new Function`/`vm.runIn*`,
  `child_process.exec[Sync]`, `pool.query` sinks; `.includes()` enum guards;
  `this` maps to `self` so class-field tracking works. 1,576 mixed
  Python+TS files (Langflow) scan in ~36s with zero crashes and zero FPs.
- **FastAPI / decorator sources**: rules can declare `kind: decorator`
  sources (`*.post`, `*.route`, ...) - route-handler parameters (including
  pydantic bodies) become untrusted automatically.
- **Class-hierarchy method resolution**: `self.m()` resolves through base
  classes and, when exactly one concrete implementation exists, through
  subclasses (abstract-hook/single-provider pattern). Ambiguous
  many-provider dispatch stays unresolved - precision first.
- **New seeded rules**: `PI-HTTP` (LLM-chosen URL fetched - SSRF/exfil,
  advisory MED) and `PI-FRAMEWORK-EXEC` (framework LLM wrappers:
  `submit_prompt`, `call_llm`, `generate_code`, ... → execution step).
  With library mode, builtin rules now flag the real Vanna CVE-2024-5565
  with no custom rule at all.
- **`palisade-sec fix`**: deterministic, offline remediation plans - a
  rule-tailored guardrail plus a regression pytest per finding, written to
  `palisade-fixes.md`. Never modifies scanned code, never calls an LLM.
- **Sanitizer verification refinements**: raises anywhere in the body
  (including except handlers) count as validation, `re.fullmatch`-style
  validator calls count, and verification follows one level of delegation.
- **Engine precision**: cross-rule dedup (one source→sink vulnerability is
  one finding; most specific rule wins); sink-named calls that resolve to
  real project functions are followed instead of flagged at the boundary;
  sources match on dotted prefixes (`req.body.q`).
- Demo: `docs/demo.svg` regenerable via `scripts/make_demo.py`.

## 0.2.0 - 2026-09-16

Driven by the proof scans against real CVE repos (docs/proof-scans.md).

- **Library mode**: `palisade-sec scan --assume-params-untrusted` (or
  `assume_params_untrusted = true` in config) treats parameters of public
  functions as untrusted sources (`param:<name>` in traces). Off by default.
- **Sanitizer strictness**: sanitizer name-matches now suppress only when
  trusted (known frameworks, `trusted: true` in rules) or when the resolved
  project-local function body shows a real allowlist/validation shape.
  A sanitizer in name only downgrades the finding to MED
  **"unverified sanitizer"** instead of silencing it - Vanna's cosmetic
  `_sanitize_plotly_code` (CVE-2024-5565) is the canonical case.
- JSON schema: `partial_defenses[].kind` added
  (`partial_defense` | `unverified_sanitizer`).
- **Engine**: abstract stub bodies (`pass` / `...` / docstring-only / bare
  raise) propagate taint like unknown calls instead of dropping it; mutating
  collection methods (`x.append(tainted)`) taint the collection; sink specs
  can declare which positional arguments are dangerous (`taint_args: [0]`
  for exec/eval - a tainted environment dict is not code execution).
- Rescanning the real vanna v0.5.5 with library mode + a one-line
  `*.submit_prompt` wrapper rule now flags exactly the CVE-2024-5565 sink
  (base.py:1998) and nothing else; an offline fixture pins this
  (tests/test_vanna_regression.py).

## 0.1.0 - 2026-09-16

Initial release: Python frontend (stdlib ast) → language-agnostic taint IR →
engine; PI-EXEC / PI-SHELL / PI-SQL rules; sanitizer resolution and
partial-defense downgrade; bounded inter-procedural propagation; `scan` and
`baseline` CLI with line-shift-resilient fingerprints; vulnerable example
app as acceptance fixtures.
