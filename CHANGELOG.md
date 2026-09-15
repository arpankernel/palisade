# Changelog

## 0.2.0 — unreleased

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
