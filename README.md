# Palisade

> **Website:** https://arpankernel.github.io/palisade/ · **Docs:** https://arpankernel.github.io/palisade/docs/

**A linter for LLM security.** Palisade statically detects prompt-injection
vulnerabilities in Python and JavaScript/TypeScript codebases - untrusted
input flowing through an LLM into a dangerous sink - in CI, before they ship.

```
untrusted input  →  LLM  →  exec / shell / raw SQL   (no sanitizer)   ⇒  finding
```

The core is offline: no API key, no signup, no network calls, pure static
analysis. An optional judgment layer (`audit`, `review`) adds AI-safety analysis
over an endpoint you configure. Everything is MIT and free to run.

```bash
uvx palisade-sec scan .
```

![palisade-sec scanning the example app](https://raw.githubusercontent.com/arpankernel/palisade/main/docs/demo.svg)

<details><summary>Same output as text</summary>

```
HIGH  app.py:31  [PI-EXEC] Prompt injection reaching code execution
  ↳ source:  question = request.json["question"]        (app.py:31)
  ↳ llm:     resp = client.chat.completions.create(     (app.py:32)
  ↳ sink:    exec(code)                                 (app.py:40)
  No sanitizer on path.  Confidence: HIGH
  Attack: crafted input makes the model emit Python that executes on your server.
  Fix:    never exec model output; sandbox + strict allowlist (denylists are bypassable).
  Refs:   CVE-2024-12366 (PandasAI); CVE-2025-3248 (Langflow, CISA KEV)
```

</details>

## Documentation

Full docs are published at **[https://arpankernel.github.io/palisade/docs/](https://arpankernel.github.io/palisade/docs/)** (source in [`docs/`](docs/index.md)):

| | |
|---|---|
| [Getting started](https://arpankernel.github.io/palisade/docs/getting-started/) | Install, first scan, reading a finding, CI gating - 5 minutes |
| [End-to-end tutorial](https://arpankernel.github.io/palisade/docs/tutorial/) | Full workflow on a sample app ([`examples/support-bot/`](examples/support-bot/)): scan → fix → verify → baseline → CI |
| [Architecture](https://arpankernel.github.io/palisade/docs/architecture/) | Frontends → taint IR → engine → rules; the precision philosophy; the safety contract |
| [CLI reference](https://arpankernel.github.io/palisade/docs/cli-reference/) | Every command, flag, exit code, config key; the stable JSON schema |
| [Rules reference](https://arpankernel.github.io/palisade/docs/rules-reference/) | All five builtin rules; pattern semantics; custom rules |
| [For AI agents](https://arpankernel.github.io/palisade/docs/agents/) | Machine contract: commands, JSON parsing, remediation policy (also [`llms.txt`](llms.txt), [`AGENTS.md`](AGENTS.md)) |
| [Roadmap](https://arpankernel.github.io/palisade/docs/roadmap/) | Phases 0–6: Measure → Distribute → Cover → Scale → Certify → Expand → Remediate |
| [Proof scans](https://arpankernel.github.io/palisade/docs/proof-scans/) | Evidence vs. real CVE repos - including the Vanna CVE-2024-5565 catch |

## Why

This exact pattern is behind real, exploited CVEs: **Langflow**
(CVE-2025-3248, on CISA KEV, exploited in the wild), **PandasAI**
(CVE-2024-12366, CVSS 9.8), **Vanna.ai** (CVE-2024-5565), **LangChain**
PAL/LLMMath chains (CVE-2023-36258, CVE-2023-29374). Almost nobody defends it
at the code level: existing tools are runtime proxies (paid, in the traffic
path) or guardrail libraries you have to know to wire in. Palisade is the
missing piece - **free, static, LLM-dataflow-aware, and CI-native**, like
ruff or semgrep but for the OWASP LLM Top-10 #1 risk.

## What it detects

| Rule | Path | Real-world precedent |
|------|------|----------------------|
| `PI-EXEC` | input → LLM → `exec` / `eval` / `new Function` / `vm.runIn*` | PandasAI, Langflow, LangChain PAL |
| `PI-SHELL` | input → LLM → `os.system` / `subprocess(shell=True)` / `child_process.exec` | Open Interpreter (by design) |
| `PI-SQL` | input → LLM → raw non-parameterized SQL (`cursor.execute`, `pool.query`) | Vanna.ai |
| `PI-FRAMEWORK-EXEC` | input → framework LLM wrapper (`submit_prompt`, `generate_code`, ...) → execution step | Vanna.ai, PandasAI |
| `PI-HTTP` | input → LLM → model-chosen URL fetched (SSRF/exfil; advisory) | OWASP LLM Top-10 |

**Measured, not asserted.** Against a pinned benchmark corpus of 26
third-party repos (17,343 files): **precision 1.000, recall 0.667, F1 0.800**
- zero false positives, with the one miss (PandasAI's dynamically dispatched
pipeline) labelled as a miss rather than deleted. The gate runs in CI, so
precision can only ratchet upward. See
[docs/proof-scans.md](https://arpankernel.github.io/palisade/docs/proof-scans/).

Sources cover Flask (`request.*`), FastAPI (`@app.post` route params and
pydantic bodies), Express (`req.body`/`req.query`), CLIs (`input()`,
`sys.argv`, `process.argv`) - and, in library mode, public function
parameters. **Scanning the real vanna v0.5.5 with
`--assume-params-untrusted` flags exactly the CVE-2024-5565 sink
(`base.py:1998`) and nothing else.**

Palisade runs **taint analysis, not grep**: it only reports a *complete*
`source → LLM → sink` data-flow path with no sanitizer in between.

- Constant developer prompt → LLM → `exec`? **Silent** - no untrusted source.
- `subprocess.run([...])` with an arg list? **Silent** - safe sink shape.
- Parameterized `cursor.execute(q, params)`? **Silent.**
- Allowlist / pydantic validation on the path? **Silent** - sanitized.
- Denylist or human-confirmation gate? **Flagged MED "risky"** - real CVEs
  were exploited despite exactly those defenses. That is deliberate.
- A "sanitizer" in name only - a project function matching `sanitize`/
  `validate` whose body never actually validates? **Flagged MED "unverified
  sanitizer"** - Vanna's cosmetic `_sanitize_plotly_code` shipped
  CVE-2024-5565 straight through such a function.
- Several rules matching one `source → sink` path? **One finding** - the
  most specific rule wins; no duplicate noise.

## Two layers: offline core, optional judgment

Palisade is one open-source tool with two layers. The distinction is not
free-versus-paid (it is all MIT and free); it is **keyless-and-offline** versus
**bring-your-own-endpoint**.

| Layer | Commands | Network | Key |
|---|---|---|---|
| **Offline core** | `scan`, `map`, `baseline`, `fix` | none | none |
| **Judgment layer** | `audit`, `review` | your endpoint | your key (`.env`) |

- `map` inventories the AI surface of a codebase (LLM calls, prompts, tools,
  agents, retrieval, dangerous flags). Offline and keyless.
- `audit` judges grounded findings: whether an agent tool has excessive agency,
  and whether a `source → LLM → sink` path is realistically exploitable. Every
  question is anchored to a fact the static analyzer verified.
- `review` composes scan + map + the semantic checks into one prioritized report
  with a **posture score** (a number and a band over *detected* findings, not a
  safety score).

The judgment layer speaks any OpenAI-compatible endpoint, configured in `.env`
(see [`.env.example`](.env.example)); **[TypeSafe](https://typesafe.ai)** is the
default and returns calibrated answers. A generic endpoint is supported as
best-effort and never blocks CI on judgment alone. The exploitability and posture
signals are **uncalibrated until scored on the corpus**; the deterministic
scanner's precision (below) is unaffected by the judgment layer.

## Install & run

```bash
# one-shot, no install
uvx palisade-sec scan path/to/project

# or
pipx run palisade-sec scan .

# or as a dev dependency
uv add --dev palisade-sec

# with the JavaScript/TypeScript frontend (tree-sitter)
uvx --from "palisade-sec[js]" palisade-sec scan .
```

Python is scanned out of the box; `.js`/`.ts`/`.tsx` files are scanned when
the `[js]` extra is installed (otherwise they're skipped with a note).

Useful flags:

```bash
palisade-sec scan . --all          # also show MED/LOW findings
palisade-sec scan . --json         # stable machine-readable output
palisade-sec scan . --report       # write palisade-report.md
palisade-sec scan . --rules ./my-rules   # add your own YAML rules
palisade-sec scan . --assume-params-untrusted   # library mode, see below
palisade-sec fix .                 # remediation plan: guardrail + test per finding
```

### `palisade-sec fix`

`fix` turns findings into a remediation plan (`palisade-fixes.md`): for each
finding, a rule-tailored guardrail (AST allowlist for exec, arg-list +
executable allowlist for shell, SELECT-only parser check for SQL, host
allowlist + private-IP block for SSRF) **plus a pytest asserting the
guardrail blocks the canonical attack**. Deterministic and offline - it
never modifies your code and never calls an LLM.

### Scanning libraries

Apps read untrusted input from `request.*` / `input()` / `sys.argv`. A
*library* has no visible caller - its public parameters ARE the untrusted
world (Vanna's `ask(question)`, CVE-2024-5565). Library mode treats the
parameters of public (non-underscore) functions as untrusted sources:

```bash
palisade-sec scan path/to/library --assume-params-untrusted
```

If the library routes LLM calls through its own wrapper method, add the
wrapper to a custom rule's `llm_signatures` (e.g. `"*.submit_prompt"`) - see
the rules guide.

## CI

Gate pull requests on **new** findings only - adopt Palisade on an imperfect
codebase without a wall of pre-existing failures:

```bash
palisade-sec baseline .                 # once; commit .palisade/baseline.json
palisade-sec scan . --ci --baseline .palisade/baseline.json
```

`--ci` exits non-zero only if a **new HIGH** finding appears. Fingerprints are
line-number independent, so refactors don't churn the baseline.

GitHub Actions:

```yaml
- uses: astral-sh/setup-uv@v5
- run: uvx palisade-sec scan . --ci --baseline .palisade/baseline.json
```

## Configuration

`pyproject.toml`:

```toml
[tool.palisade]
paths_ignore = ["migrations/*", "sandbox/*"]
include_tests = false   # tests/** and conftest.py are skipped by default
max_hops = 3            # inter-procedural depth bound
assume_params_untrusted = false   # library mode (see "Scanning libraries")
```

Or the same keys in `.palisade.toml`.

## Custom rules

Rules are plain YAML validated by a pydantic schema - sources, LLM call
signatures, sinks, sanitizers, partial defenses. Adding coverage for a new
framework is a small PR with **no engine changes**. See
[`src/palisade_sec/rules/README.md`](https://github.com/arpankernel/palisade/blob/main/src/palisade_sec/rules/README.md) for
the 5-minute guide.

## Architecture

```
source ──▶ language frontends ──────────────────▶ normalized taint IR
           Python (stdlib ast)                          │
           JS/TS (tree-sitter, optional extra)          │
                              language-agnostic engine ─┤ taint propagation,
                              sanitizer resolution, confidence scoring
                                                        │
             YAML rules ──▶ findings ──▶ baseline diff ──▶ terminal / json / md
```

The frontend/IR split is the scalability story - proven, not promised: the
JS/TS frontend landed with **zero engine changes**, and the same YAML rules
match both languages (`chat.completions.create`, `eval`,
`child_process.exec` are just dotted paths). Go and more come the same way.

## Safety of the tool itself

- Palisade **never executes, imports, or evaluates scanned code** - it only
  parses source text with `ast.parse`.
- `scan` makes **no network calls** and needs no API key or account.
- No telemetry. Nothing leaves your machine.

## An honest note on scope

Palisade is **one layer** of defense against **one class** of vulnerability.
A clean scan means no *detected* injection-to-sink path - it does not mean
your application is secure. Keep your runtime guardrails, permissions
boundaries, and sandboxes; Palisade complements them, before merge.

## License

MIT
