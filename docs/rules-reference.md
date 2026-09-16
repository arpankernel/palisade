# Rules reference

Rules are YAML data validated by a pydantic schema
([`schema.py`](../src/palisade_sec/rules/schema.py)). The engine is generic:
**a new rule needs zero engine changes.** For the 5-minute "write a rule"
guide, see [`rules/README.md`](../src/palisade_sec/rules/README.md); this
page is the reference.

## The five builtin rules

| Rule | Severity | Sinks | Real-world precedent |
|---|---|---|---|
| `PI-EXEC` | high | `exec`, `eval`, `compile`, `PythonREPL.run`, `new Function`, `vm.runIn*` | PandasAI CVE-2024-12366, Langflow CVE-2025-3248 class, LangChain PAL CVE-2023-36258 |
| `PI-SHELL` | high | `os.system`, `os.popen`, `subprocess.*` **with `shell=True`**, `subprocess.getoutput`, `child_process.exec[Sync]` | Open Interpreter (by design) |
| `PI-SQL` | high | `*.execute`/`executemany`/`executescript`, Django `*.raw`, JS `pool/db/conn/client.query` - **non-parameterized form only** | Vanna.ai CVE-2024-5565 / CVE-2024-5826 |
| `PI-FRAMEWORK-EXEC` | high | exec-family **plus** `*.run_code`, `*.execute_code`, `*.execute_plan` | Vanna (`submit_prompt`), PandasAI (code pipelines) |
| `PI-HTTP` | **med (advisory)** | `requests.*`, `httpx.*`, `urlopen` - URL argument only | SSRF / exfiltration, OWASP LLM Top-10 |

All five share the source set (Flask `request.*`, FastAPI/route decorators,
Express `req.*`, `input()`, `sys.argv`, `process.argv`) and the LLM
signature set (OpenAI/Anthropic/litellm/ollama/Gemini SDK paths + LangChain
`chain.run`-style receiver names). `PI-FRAMEWORK-EXEC` additionally treats
project **wrapper methods** as LLM boundaries: `*.submit_prompt`,
`*.call_llm`, `*.ask_llm`, `*.generate_code`, `*.generate_sql`,
`*.chat_completion`, and friends - the shape agent/pipeline frameworks
actually use.

`PI-HTTP` is deliberately MED: browsing agents make LLM-chosen URLs
intentional in some codebases. It appears with `--all`, never gates `--ci`,
and is the model for future advisory rules (PII egress, agent loops).

## Rule schema

```yaml
id: PI-MYRULE            # ^[A-Z][A-Z0-9-]{2,31}$ - same id overrides a builtin
title: One-line human title
severity: high           # high | med | low
description: >
  What the vulnerable pattern is and why it is exploitable.
sources:                 # where untrusted input enters
  - kind: attribute
    patterns: ["request.json", "req.body", "sys.argv"]
  - kind: call
    patterns: ["input", "request.get_json"]
  - kind: decorator      # route handlers: params become sources
    patterns: ["*.route", "*.get", "*.post"]
llm_signatures:          # what an LLM call looks like
  - kind: call
    patterns: ["chat.completions.create", "messages.create", "*.submit_prompt"]
sinks:
  - kind: call
    patterns: ["exec", "*.execute"]
    taint_args: [0]              # only these positional args are dangerous
    require_kwargs: {shell: true}   # only a sink when this kwarg is literally true
    safe_if_extra_args: true        # execute(q, params) is parameterized → safe
sanitizers:
  - kind: call
    trusted: true                # framework validators: name match suppresses
    patterns: ["model_validate", "parse_obj", "schema.load"]
  - kind: call                   # heuristics: suppress only if body verifies
    patterns: ["validate", "sanitize", "allowlist"]
partial_defenses:                # NEVER suppress - downgrade to MED "risky"
  - kind: call
    patterns: ["denylist", "blocked", "confirm", "auto_run"]
references: ["CVE-XXXX-XXXXX (project)"]
attack: One concrete attacker sentence.
fix: The specific change a developer should make.
```

## Pattern semantics

Strict categories (`sources`, `llm_signatures`, `sinks`) match
**alias-resolved dotted paths** - `import subprocess as sp; sp.run` and
`const {exec} = require("child_process")` are seen as `subprocess.run` and
`child_process.exec`:

| Pattern | Matches | Doesn't match |
|---|---|---|
| `exec` | `exec` | `obj.exec` (single segment = exact only) |
| `request.json` | `request.json`, `flask.request.json`, **and deeper reads** (`req.body.q` matches `req.body`) | `request.jsonify` |
| `chat.completions.create` | `client.chat.completions.create` | `completions.update` |
| `*.execute` | `cur.execute`, `conn.execute` | bare `execute` |

`kind: decorator` patterns match **decorators only** (a function decorated
`@app.post(...)` gets tainted params); they are never matched against
ordinary calls - `requests.post(...)` is not a source.

Defense categories (`sanitizers`, `partial_defenses`) match as
**case-insensitive substrings** of the call path, so `validate` also catches
`validate_code` and `CodeModel.model_validate_json`.

## Sanitizer tiers (v0.2+)

- **`trusted: true`** - known validation frameworks. Name match fully
  suppresses.
- **Untrusted (default)** - name heuristics. A match suppresses only when
  the call resolves to a project-local function whose body shows a real
  validation shape: a membership test, a guard branch that raises/returns,
  a raise anywhere (except handlers included), a strict-matcher call
  (`re.fullmatch`, `uuid.UUID`, …), or one level of delegation to such a
  body. A **sanitizer in name only** (cosmetic `.replace()` - Vanna's
  `_sanitize_plotly_code`, CVE-2024-5565) downgrades the finding to
  **MED "unverified sanitizer"** instead of silencing it.
- Unresolvable third-party calls keep the benefit of the doubt; promote the
  ones you rely on to a `trusted` spec in a custom rule.

Also full sanitizers, engine-side: `int()`/`float()`/`bool()` casts and
literal-enum membership guards (`if x in ("a", "b")`, JS
`["a","b"].includes(x)`).

## Partial defenses

Denylists, blocklists, confirmation gates, `auto_run` flags. They **never
suppress** - the finding survives at MED "risky" with the defense named in
the output. This is philosophy, backed by CVEs: LangChain PAL's denylist and
Open Interpreter's confirmation gate were both walked through in the wild.

## Overlap and dedup

When several rules match the same source → sink path (e.g. `PI-EXEC` and
`PI-FRAMEWORK-EXEC` on one exec), the scan reports **one finding** - highest
severity wins, ties go to the earlier-loaded (more specific) rule. A
sink-named call (`*.execute_code`) that resolves to a real project function
is followed into instead of flagged at the boundary, so the finding lands on
the true sink line.

## Custom rules in practice

```bash
palisade-sec scan . --rules ./security/rules
```

- A rule file with an existing `id` **overrides** the builtin - tune without
  forking.
- The classic custom rule: your codebase routes LLM calls through
  `self.inference(...)` - add `"*.inference"` to `llm_signatures` in a copy
  of `PI-FRAMEWORK-EXEC`.
- Contribution bar (see [CONTRIBUTING.md](../CONTRIBUTING.md)): every rule
  PR ships a must-flag fixture **and** a same-shaped must-stay-silent
  fixture. The silent one matters more.
