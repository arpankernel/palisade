# Palisade rules

Rules are YAML data validated by a pydantic schema
([`schema.py`](schema.py)). The engine is generic: **a new rule needs zero
engine changes** — you only describe what to match.

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
   more — Palisade's contract is precision over recall.

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

Defense categories (`sanitizers`, `partial_defenses`) match as
**case-insensitive substrings** of the call path, so `validate` also catches
`validate_code` and `CodeModel.model_validate_json`.

A rule id that already exists overrides the builtin — that's how you tune a
builtin rule for your codebase without forking.

## v1 limitations worth knowing

- LangChain-style signatures like `chain.run` match on the receiver variable
  name (`chain`, `llm`, `agent`). If your code names the chain something
  else, add your name to a custom rule.
- Sinks and sanitizers behind third-party classes Palisade can't see into
  (e.g. `self.db.raw_query(...)`) are matched by pattern only; project-local
  wrapper *functions* are followed one level in.
