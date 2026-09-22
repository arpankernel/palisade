# Changelog

## Unreleased

### Added

- **Jupyter notebook support (`.ipynb`).** A new frontend reassembles a
  notebook's code cells into one Python source - a name bound in one cell and
  used in a later one, exactly like top-level statements in a `.py` file -
  and delegates entirely to `PythonFrontend`, so every existing rule, the
  taint engine, and PI-AGENT-HANDOFF all work on notebooks with zero engine
  changes. Non-code cells and IPython line/cell magics (`%matplotlib inline`,
  `!pip install`, `%%time`) are blanked rather than passed to `ast.parse`,
  which would reject them outright. Reported line numbers follow the
  `jupyter nbconvert --to script` convention (a `# In[N]:` marker line per
  cell), so a finding is traceable back to its cell. A notebook whose kernel
  is not Python (`metadata.language_info.name`) is skipped with a clear
  reason rather than guessed at. `.ipynb_checkpoints/` joins the
  always-excluded directory list.

## 0.5.1 - 2026-09-22

A pre-launch hardening release. Three independent audits (fresh-install
behaviour, the tool's own security, and every public claim) ran against the
published 0.5.0. Everything they reproduced is fixed here, each with a
regression test that fails on 0.5.0. Re-validated on the pinned 26-repo
benchmark: precision **1.000** (0 false positives), recall 0.667 unchanged,
and no new finding of any severity in the 23 clean repos.

### Security

- **Output writes no longer follow planted symlinks.** A repository that
  shipped `palisade-report.md`, `palisade-fixes.md`, `palisade-review.md` or a
  `.palisade` directory as symlinks made `scan --report`, `fix`, `review
  --report` and `baseline` overwrite files outside it (e.g. `~/.bashrc`) when
  run inside an untrusted clone. Writes now refuse a symlink at the file or
  any directory below the working directory, and open with `O_NOFOLLOW`.
- **Scanned text is shown, never interpreted.** Control characters (terminal
  escape sequences) and Unicode bidi overrides ("Trojan Source") in snippets
  and file paths are neutralized into visible escapes, so scanned code can no
  longer rewrite Palisade's own terminal output. Backticks and pipes in paths
  and snippets can no longer break out of markdown report formatting.
- **A cloned repo's `.env` cannot redirect your key.** An endpoint chosen by a
  `.env` file is used only with a key from that same file.
- **A repo's own config cannot point `rules_dir` outside the repo.** `--rules`
  is unrestricted.

### Fixed

- **Only allowlist-shaped sanitizers silence a finding.** 0.5.0 silenced
  PI-EXEC when the sanitizer was a denylist search of the input (`if "import"
  in code: raise`), a length check, or any raise (e.g. `ast.parse` in a
  try/except), contradicting "downgrade, never silence". Those now land as
  MED "unverified sanitizer". Silencing requires an allowlist lookup, an AST
  node-type allowlist, an enum-literal guard, or a strict matcher such as
  `re.fullmatch` (now also recognized inside an `if` condition).
- **`review`, `audit` and `redteam --execute` no longer crash on a plain
  install.** Without the `[judge]` extra they printed an httpx
  `ModuleNotFoundError` traceback. `review` now runs taint-only and says why;
  `audit` and `redteam --execute` exit 2 with an install hint.
- **An empty scan is never a pass.** Scanning zero files (a JS/TS repo
  without `[js]`, an over-broad ignore, an empty target) printed a green tick
  and passed `--ci`. It now warns in every output, and `scan`/`review`/
  `audit --ci` exit 2. SARIF records the run as unsuccessful.
- **A copy-pasted known vulnerability is a new finding.** Baseline
  fingerprints are line-independent, so a duplicate passed `--ci`; the diff
  now compares occurrence counts.
- **`redteam --execute`: an unreachable target is not "0 landed".** Attacks
  with no response are reported as errors, are never scored or sent to the
  judge, and fail `--ci`.
- **`.env` is read from the working directory.** 0.5.0 searched from the
  installed package, so the documented `.env` setup never worked for pip/uvx.
- **gitignore negations (`!src/`) are honoured.** An allowlist-style
  `.gitignore` previously hid the whole source tree.
- **Only the real TypeSafe endpoint counts as verified.** Pointing the
  TypeSafe adapter elsewhere now gets the unverified-backend posture cap.
- **Rule references are accurate.** PI-EXEC no longer cites Langflow's
  CVE-2025-3248 (no LLM on its path; the corpus scores it out of contract),
  and PI-SQL no longer cites Vanna's CVE-2024-5565/-5826 (exec bugs). A test
  fails if a rule cites a CVE the corpus scores clean.

### Changed

- **Exit code 3 means an internal error** (a bug, not a finding). 0.5.0 exited
  1 on a crash, the same as "found a HIGH". `PALISADE_DEBUG=1` shows the
  traceback.
- Exit code 2 now also covers: a `--ci` run that scanned nothing, a missing
  `[judge]` extra or key, an explicitly named `--config`/`--rules` that does
  not exist, a refused output path, and red-team attacks that got no response
  under `--ci`.
- A judge outage during `review` falls back to taint-only; it never fails the
  deterministic `--ci` gate. During `audit` it is a clean exit 2.
- Every command reports warnings, skipped files and notes (on stderr, so
  `--json` stays parseable). JS/TS files skipped for want of `[js]` are a
  warning, and files that failed to parse are counted beside the verdict.
- `redteam --variants` is range-checked against the templates that exist
  (1-2); larger values silently produced duplicates.
- The precision harness prints the number of files it scanned.
- `.env.example` no longer sets the endpoint and model (both have defaults).

### Internal

- New CI job **"Plain install (no extras)"**: builds the wheel and drives every
  command from a fresh venv with no extras (`scripts/smoke_install.sh`). It
  also runs in the release workflow before publishing. It fails on the 0.5.0
  wheel and passes on 0.5.1.

## 0.5.0 - 2026-09-21

The applied agentic-safety layer. The deterministic core (`scan`, `map`,
`baseline`, `fix`) stays offline and keyless. A new judgment layer is
bring-your-own-endpoint: it reads an endpoint and key from `.env` and is used
only by `audit` and `review`. Before release, an adversarial self-audit hardened
the engine: it found and fixed a critical sanitizer-silencing bug, two taint
false negatives, false-positive vectors in the multi-agent analysis, a vacuous
calibration metric, and a SARIF path bug - each with a permanent regression test.
Re-validated on the pinned 26-repo benchmark: precision **1.000**, 0 false
positives, the Vanna CVE still caught.

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

### Fixed

- **Sanitizer silencing bypass (critical).** A sanitizer body that only
  transformed its input and returned it (`code = code.replace(...); return
  code` - the Vanna CVE-2024-5565 shape) was treated as verified and fully
  suppressed the finding, because any `raise`, terminating guard, or `re.match`
  counted as validation. A transform-and-return body is now cosmetic unless it
  carries a strong signal (a membership test or `re.fullmatch` family call);
  `re.match` was dropped from the validator set. This restores the documented
  "downgrade, never silence" contract.
- **Empty SQL parameters no longer disarm the sink.** `cursor.execute(sql, ())`
  (or `[]`, `{}`, `params={}`) binds nothing, so the tainted SQL string is what
  executes; it is no longer treated as parameterized. A real, non-empty binding
  still suppresses.
- **`try`/`except` no longer erases taint.** `try: code = <llm output> except:
  code = "safe"` followed by `exec(code)` dropped the finding, because handler
  state overwrote the try-body state. The two branches are now joined.
- **`PI-AGENT-HANDOFF` taint is cast/sanitizer aware and flow-sensitive.** The
  multi-agent finding (which gates `scan --ci`) no longer treats `run(agent,
  int(x))` or `run(agent, sanitize(x))` as untrusted, and an unconditional clean
  reassignment now clears taint - closing false-positive vectors that could break
  a user's build.
- **Calibration no longer reports a vacuous precision.** A signal with no
  positive predictions (or no positive labels) reported precision `1.000` and
  cleared the gate. Precision and recall are now undefined (null) when their
  denominator is zero; the gate requires a signal to be exercised, and an
  unexercised signal is reported rather than silently passing.
- **SARIF URIs are relative to the repository root.** Finding paths are relative
  to the scan target, so a subdirectory scan (`scan src`) mislocated every GitHub
  code-scanning alert. `to_sarif` now takes a base and the CLI prepends the scan
  base relative to the working directory.

### Performance

- **`resolve()` is no longer O(n^2) on large TypeScript repos.** The dotted-suffix
  fallback scanned the whole function registry per call site; it now consults a
  last-segment index. gemini-cli `packages/core/src` (465 files) went from not
  finishing in 90s to 13.9s, with byte-identical findings.

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
