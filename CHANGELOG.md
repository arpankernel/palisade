# Changelog

## 0.3.0 — unreleased

The "everything deferred" release: multi-language, framework-aware, and
able to propose fixes.

- **JavaScript/TypeScript frontend** (tree-sitter, optional `[js]` extra):
  `.js`/`.mjs`/`.cjs`/`.jsx`/`.ts`/`.tsx` lower into the same taint IR with
  **zero engine changes** — the multi-language architecture, proven. Express
  sources (`req.body`, `req.query`), `eval`/`new Function`/`vm.runIn*`,
  `child_process.exec[Sync]`, `pool.query` sinks; `.includes()` enum guards;
  `this` maps to `self` so class-field tracking works. 1,576 mixed
  Python+TS files (Langflow) scan in ~36s with zero crashes and zero FPs.
- **FastAPI / decorator sources**: rules can declare `kind: decorator`
  sources (`*.post`, `*.route`, ...) — route-handler parameters (including
  pydantic bodies) become untrusted automatically.
- **Class-hierarchy method resolution**: `self.m()` resolves through base
  classes and, when exactly one concrete implementation exists, through
  subclasses (abstract-hook/single-provider pattern). Ambiguous
  many-provider dispatch stays unresolved — precision first.
- **New seeded rules**: `PI-HTTP` (LLM-chosen URL fetched — SSRF/exfil,
  advisory MED) and `PI-FRAMEWORK-EXEC` (framework LLM wrappers:
  `submit_prompt`, `call_llm`, `generate_code`, ... → execution step).
  With library mode, builtin rules now flag the real Vanna CVE-2024-5565
  with no custom rule at all.
- **`palisade-sec fix`**: deterministic, offline remediation plans — a
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

## 0.2.0 — 2026-09-16

Driven by the proof scans against real CVE repos (docs/proof-scans.md).

- **Library mode**: `palisade-sec scan --assume-params-untrusted` (or
  `assume_params_untrusted = true` in config) treats parameters of public
  functions as untrusted sources (`param:<name>` in traces). Off by default.
- **Sanitizer strictness**: sanitizer name-matches now suppress only when
  trusted (known frameworks, `trusted: true` in rules) or when the resolved
  project-local function body shows a real allowlist/validation shape.
  A sanitizer in name only downgrades the finding to MED
  **"unverified sanitizer"** instead of silencing it — Vanna's cosmetic
  `_sanitize_plotly_code` (CVE-2024-5565) is the canonical case.
- JSON schema: `partial_defenses[].kind` added
  (`partial_defense` | `unverified_sanitizer`).
- **Engine**: abstract stub bodies (`pass` / `...` / docstring-only / bare
  raise) propagate taint like unknown calls instead of dropping it; mutating
  collection methods (`x.append(tainted)`) taint the collection; sink specs
  can declare which positional arguments are dangerous (`taint_args: [0]`
  for exec/eval — a tainted environment dict is not code execution).
- Rescanning the real vanna v0.5.5 with library mode + a one-line
  `*.submit_prompt` wrapper rule now flags exactly the CVE-2024-5565 sink
  (base.py:1998) and nothing else; an offline fixture pins this
  (tests/test_vanna_regression.py).

## 0.1.0 — 2026-09-16

Initial release: Python frontend (stdlib ast) → language-agnostic taint IR →
engine; PI-EXEC / PI-SHELL / PI-SQL rules; sanitizer resolution and
partial-defense downgrade; bounded inter-procedural propagation; `scan` and
`baseline` CLI with line-shift-resilient fingerprints; vulnerable example
app as acceptance fixtures.
