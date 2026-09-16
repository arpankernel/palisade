# Proof scans: Palisade v0.1.0 vs. the real CVE repos

**Date:** 2026-09-16 · **Palisade:** v0.1.0 · **Method:** scanned the last
vulnerable tag of each project that motivated Palisade's rules, then traced
each CVE's actual code path by hand to classify hits and misses.

## Summary

| Repo (tag) | CVE | Files scanned | Findings | CVE caught? |
|---|---|---|---|---|
| vanna-ai/vanna `v0.5.5` | CVE-2024-5565 (LLM → plotly `exec`) | 45 | 0 | **No** - see V1/V2/V3 |
| sinaptik-ai/pandas-ai `v2.4.2` | CVE-2024-12366 (LLM code → `exec`) | 292 | 0 | **No** - see P1 |
| langflow-ai/langflow `1.2.0` | CVE-2025-3248 (request → `exec`) | 738 | 0 | **No** - out of contract, see L1 |

What held up, and matters as much as the misses:

- **Zero false positives across 1,075 real-world files.** *(Figure from
  this original pass; superseded by the formal corpus below.)* The precision
  contract ("a false positive is worse than a miss") survived contact with
  three large, messy, real codebases.
- **Zero crashes, zero skipped files**, and the largest repo (Langflow,
  738 Python files) scanned in ~10 seconds.
- The engine *does* catch all three CVE **patterns** when they appear in
  app-shaped code - the `examples/vulnerable-app` fixtures mirror each one
  (PandasAI-style exec, Vanna-style text-to-SQL, shell) and are flagged with
  full traces.

The misses are structural, not random, and each one maps to a concrete
roadmap item. That is exactly what these scans were for.

## Why each CVE was missed

### Vanna (CVE-2024-5565) - three independent blockers

The real chain lives entirely in `src/vanna/base/base.py`:
`ask(question)` → `generate_plotly_code(...)` (line 686) →
`self.submit_prompt(message_log)` (line 707, the LLM call) →
`self._sanitize_plotly_code(...)` (line 709) →
`get_plotly_figure(plotly_code)` → `exec(plotly_code, globals(), ldict)`
(line 1998).

- **V1 - library entry point.** The untrusted input is the `question`
  *parameter* of a public API method. Palisade v1 sources are app-shaped
  (`request.*`, `input()`, `sys.argv`); function parameters are only tainted
  when the caller is visible. Libraries have no visible caller.
  → Roadmap: opt-in **library mode** (`--assume-params-untrusted`) tainting
  public-function parameters, per the PRD's "params marked untrusted".
- **V2 - abstract provider dispatch.** `submit_prompt` is `@abstractmethod`
  in `VannaBase`; the actual `client.chat.completions.create` lives in
  provider subclasses (`openai_chat.py` etc.). Same-class method resolution
  can't link them, so the LLM hop is invisible.
  → Roadmap: class-hierarchy-aware method resolution (resolve `self.m()`
  through subclass implementations when unambiguous enough); short-term, a
  custom rule adding `*.submit_prompt` to `llm_signatures` closes this for
  Vanna-style codebases.
- **V3 - a "sanitizer" in name only.** `_sanitize_plotly_code` merely strips
  `fig.show()` - cosmetic, and the CVE was exploited straight through it.
  Palisade's lenient name-based sanitizer matching would have *suppressed*
  the finding had V1/V2 been fixed. This cuts against philosophy #7.
  → Roadmap: tighten sanitizer resolution - name-match alone should perhaps
  downgrade (like a partial defense) rather than suppress, unless the
  sanitizer body shows allowlist/validation semantics.

### PandasAI (CVE-2024-12366) - P1: pipeline-object indirection

The sink is `exec(code, env)` in `pandasai/pipelines/chat/code_cleaning.py:493`,
but data flows to it through a chain of pipeline *step objects*
(`CodeGenerator` → `CodeCleaning` → `CodeExecution`) invoked dynamically by a
pipeline runner. Function-level bounded taint cannot follow
`pipeline.run()` dispatch between step instances.
→ Roadmap: recognize common pipeline/chain frameworks via rules (step-class
signatures), or model "output of step N feeds step N+1" for known runners.
Honest assessment: full generality here is out of scope for a bounded static
tool; framework-specific rules are the pragmatic path.

### Langflow (CVE-2025-3248) - L1: not an LLM-path vulnerability

`POST /api/v1/validate/code` passes the request body **directly** to
`validate_code()` → `exec()` (`langflow/utils/validate.py`). There is no LLM
between source and sink - this is classic unauthenticated code injection,
squarely Bandit-B102 territory, and Palisade's contract (complete
source → **LLM** → sink path) correctly excludes it. It remains strong
motivation for the *problem space* (AI tooling ships `exec` on untrusted
input), but it is not a Palisade v1 target.
→ Roadmap: FastAPI sources (pydantic body params, route args) are still
worth adding for the LLM-path cases in FastAPI apps.

## Methodology notes

- Tags scanned are the last releases before each fix landed.
- Scans ran with `--all --json`; nothing was hidden by severity filtering.
- "CVE caught" means a finding whose sink is the CVE's actual sink line.

## Status update - v0.2 (2026-09-16)

Items 1–3 below are implemented:

- **Library mode** shipped as `--assume-params-untrusted` (also a config
  key). Parameters of public functions become untrusted sources
  (`param:<name>` in the trace).
- **Sanitizer strictness** shipped: name-heuristic sanitizer matches now
  suppress only when the resolved project-local body shows a real
  allowlist/validation shape; otherwise the finding is downgraded to MED
  "unverified sanitizer". Known frameworks are marked `trusted: true` in the
  rules and still suppress on name match.
- **The real CVE is now caught.** Rescanning the actual vanna `v0.5.5` tree
  with library mode plus a custom rule adding `*.submit_prompt` to
  `llm_signatures` yields exactly one finding - the CVE-2024-5565 sink
  itself:

  ```
  MED  src/vanna/base/base.py:1998   exec(plotly_code, globals(), ldict)
       source: param:question (ask(), base.py:1594)
       llm:    self.submit_prompt
       unverified sanitizer: self._sanitize_plotly_code
  ```

  Zero other findings across the repo. Getting here required two further
  engine fixes the real code exposed: abstract stub methods (`...`/`pass`/
  bare-raise bodies) now propagate taint instead of silently dropping it,
  and sinks declare which argument is dangerous (`taint_args: [0]` - a
  tainted `exec(..., globals(), ldict)` environment dict is not code
  execution). An offline fixture mirroring this exact shape is pinned by
  tests/test_vanna_regression.py.

Still open from this list: FastAPI sources (L1) and pipeline-framework rules
(P1); class-hierarchy resolution (the custom-rule recipe covers V2 for now).

## Status update - v0.3 (2026-09-16)

Everything above is now closed:

- **L1 (FastAPI sources)**: decorator-kind rule sources ship in all builtin
  rules; `@app.post` handler params (incl. pydantic bodies) are sources.
- **V2 (class-hierarchy resolution)**: `self.m()` resolves through bases and
  unique concrete subclass implementations; ambiguous provider dispatch
  stays unresolved by design.
- **P1 (pipeline-framework rules)**: `PI-FRAMEWORK-EXEC` ships wrapper-LLM
  signatures (`submit_prompt`, `call_llm`, `generate_code`, ...). Builtin
  rules + library mode now flag the real vanna v0.5.5 CVE sink with **no
  custom rule**. PandasAI v2's fully dynamic pipeline dispatch remains out
  of reach for bounded static analysis - documented, not hidden.
- Also landed: the JS/TS tree-sitter frontend (zero engine changes - the
  1,576 mixed-language Langflow tree scans in ~36s, still zero FPs) and the
  offline `fix` command.

**Re-derived totals (v0.3.2, JS frontend enabled).** Rescanning all three
repos with the current builtin rules: vanna 45 files, PandasAI 419, Langflow
1,576 - **2,040 files total, zero false positives, zero crashes, zero files
skipped**. The only finding across all three is Vanna's CVE-2024-5565 sink at
`base.py:1998`, and it is now caught by the *default* rules (PI-FRAMEWORK-EXEC
via the `input()` source) without needing library mode. Earlier drafts of this
report quoted "~2,600 files"; that double-counted Langflow's Python files, and
is corrected here. *(That pass counted only the three CVE
repos; the authoritative figure is now the 26-repo benchmark corpus in
"Formal benchmark corpus" below.)*


## Formal benchmark corpus (Phase 0, 2026-09-16)

The ad-hoc scans above became a pinned, labelled corpus: 26 third-party repos
(2 at known-vulnerable releases, 1 later release, 23 clean popular AI repos as
the anti-overfitting half), cloned at recorded SHAs by `corpus/fetch.py` and
scored by `scripts/precision.py`.

| Metric | Value |
|--------|-------|
| Repos | 26 |
| Files scanned | 17,343 |
| Precision | **1.000** (tp=2, fp=0) |
| Recall | **0.667** (tp=2, fn=1) |
| F1 | **0.800** |

| Repo | Expected | Result |
|------|----------|--------|
| vanna v0.5.5 | `base.py:1998` (CVE-2024-5565) | found, MED (cosmetic sanitizer downgrades it) |
| vanna v0.7.9 | `base.py:2088` | found; the same shape survives into the later release |
| PandasAI v2.4.2 | `code_execution.py:174` (CVE-2024-12366) | **missed** |
| Langflow 1.2.0 | nothing | silent, correctly |
| 22 clean repos | nothing | silent, zero false positives |

**The miss is recorded, not hidden.** PandasAI's exec sits behind pipeline step
objects dispatched dynamically at runtime, which bounded static taint cannot
follow. Deleting that label would flatter recall to 1.000; keeping it holds the
gap visible until the engine closes it.

**Langflow is scored as clean, not as a miss.** Its CVE reaches exec with no LLM
anywhere on the path, so it is plain code injection rather than prompt
injection, and out of Palisade's contract by design. It stays in the corpus as
1,576 files of real AI-adjacent code that must stay silent.

### What building this corpus caught

Pointing the harness at real repos surfaced four defects our own fixtures never
could:

- **One sink reported twice.** Vanna's exec is reached by both `input()` and a
  public parameter; dedup keyed on source-and-sink and emitted duplicates. It
  now keys on the sink and records collapsed duplicates in `count`.
- **A 40 KB output leak.** Scanning vanna printed the scanned file's own CSS to
  stderr, because `ast.parse` raises `SyntaxWarning` and Python echoes the whole
  source line, bypassing the 200-char snippet redaction.
- **Recall was scored wrongly.** The harness counted only HIGH findings, which
  would have marked the real Vanna CVE a false negative, since Palisade
  deliberately downgrades it to MED.
- **The gate passed vacuously.** The first full run reported precision=1.000 on
  tp=0 fp=0 fn=0, because the corpus carried `cve:` annotations but no `expect:`
  labels. The harness now fails when it measures nothing.

## Takeaways for v0.2

Priority order implied by these scans:

1. **Library mode** (`--assume-params-untrusted`) - unlocks the entire
   library-audit use case (V1).
2. **Sanitizer strictness** - name-only sanitizer matches downgrade instead
   of suppress (V3). Keeps FP=0 shape while honoring philosophy #7.
3. **Custom-rule story for wrapper LLM methods** - document `*.submit_prompt`
   -style signatures now; class-hierarchy resolution later (V2).
4. **FastAPI sources** (L1).
5. Framework-specific pipeline rules (P1) - last; lowest generality per
   effort.
