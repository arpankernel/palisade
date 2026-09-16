# Palisade rules

Rules are YAML data validated by a pydantic schema
([`schema.py`](schema.py)). The engine is generic: **a new rule needs zero
engine changes** - you only describe what to match.

## Add a rule in 5 minutes

1. Copy an existing rule (e.g. [`pi-exec.yaml`](pi-exec.yaml)) into this
   directory (builtin) or your own directory (used via `--rules <dir>`).
2. Fill in the fields:

```yaml
id: PI-MYRULE            # UPPERCASE, unique
title: One-line human title
severity: high           # high | med | low
description: >
  What the vulnerable pattern is and why it is exploitable.
sources:                 # where untrusted input enters
  - kind: attribute
    patterns: ["request.json", "sys.argv"]
  - kind: call
    patterns: ["input"]
llm_signatures:          # what an LLM call looks like
  - kind: call
    patterns: ["chat.completions.create", "messages.create"]
sinks:                   # the dangerous operation
  - kind: call
    patterns: ["exec", "*.execute"]
    # optional sink-shape guards:
    # require_kwargs: {shell: true}   # only a sink when shell=True
    # safe_if_extra_args: true        # execute(q, params) is parameterized -> safe
sanitizers:              # full defenses -> suppress the finding
  - kind: call
    patterns: ["validate", "allowlist", "model_validate"]
partial_defenses:        # weak defenses -> downgrade to MED "risky", still flag
  - kind: call
    patterns: ["denylist", "confirm", "auto_run"]
references:
  - "CVE-XXXX-XXXXX (project)"
attack: One concrete sentence describing what an attacker does.
fix: The specific change a developer should make.
```

3. Test it: `palisade-sec scan your/fixture --rules path/to/dir --all`.
4. Open a PR with the rule **plus a fixture**: one file that must be flagged
   and one same-shaped file that must stay silent. The silent one matters
   more - Palisade's contract is precision over recall.

## Pattern semantics

Strict categories (`sources`, `llm_signatures`, `sinks`) match dotted paths
after import-alias resolution (`import subprocess as sp` → `sp.run` is seen
as `subprocess.run`):

| Pattern | Matches | Doesn't match |
|---------|---------|---------------|
| `exec` | `exec` | `obj.exec` (single-segment = exact) |
| `request.json` | `request.json`, `flask.request.json` | `request.jsonify` |
| `chat.completions.create` | `client.chat.completions.create` | `completions.update` |
| `*.execute` | `cur.execute`, `conn.execute` | bare `execute` |

A source spec may use `kind: decorator` (e.g. `*.post`, `*.route`): functions
carrying a matching decorator are treated as web entry points and their
parameters become untrusted sources. Decorator patterns are never matched
against ordinary calls (`requests.post` is not a source).

Patterns are language-neutral dotted paths: the same rule matches
`client.chat.completions.create` in Python and JavaScript, `eval` in both,
and `child_process.exec` after `const { exec } = require("child_process")`
alias resolution.

Defense categories (`sanitizers`, `partial_defenses`) match as
**case-insensitive substrings** of the call path, so `validate` also catches
`validate_code` and `CodeModel.model_validate_json`.

Sanitizer specs come in two tiers (since v0.2):

- `trusted: true` - known validation frameworks (pydantic `model_validate`,
  marshmallow `schema.load`, `shlex.quote`, ...). A name match fully
  suppresses the finding.
- default (untrusted) - name heuristics like `validate`/`sanitize`/`allow`.
  A match suppresses only when the call resolves to a project-local function
  whose body shows a real allowlist/validation shape (a membership test, or
  a guard branch that raises/returns). A sanitizer in name only - e.g. a
  cosmetic `.replace()` like Vanna's `_sanitize_plotly_code`
  (CVE-2024-5565) - downgrades the finding to MED "unverified sanitizer"
  instead of silencing it. Unresolvable third-party calls keep the benefit
  of the doubt; promote the ones you rely on to a `trusted` spec.

A rule id that already exists overrides the builtin - that's how you tune a
builtin rule for your codebase without forking.

## v1 limitations worth knowing

- LangChain-style signatures like `chain.run` match on the receiver variable
  name (`chain`, `llm`, `agent`). If your code names the chain something
  else, add your name to a custom rule.
- Sinks and sanitizers behind third-party classes Palisade can't see into
  (e.g. `self.db.raw_query(...)`) are matched by pattern only; project-local
  wrapper *functions* are followed one level in.
- An LLM call behind an abstract provider method (Vanna's
  `self.submit_prompt`, implemented per provider in subclasses) is invisible
  to same-class resolution. Recipe: add the wrapper to `llm_signatures` in a
  custom rule (`"*.submit_prompt"`) and scan with
  `--assume-params-untrusted` for library code - this combination catches
  the CVE-2024-5565 shape (see tests/test_vanna_regression.py).
