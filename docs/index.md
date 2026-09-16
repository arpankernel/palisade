# Palisade documentation

> Rendered and searchable at **https://arpankernel.github.io/palisade/docs/** - this directory is the source.

**Palisade is a linter for LLM security**: it statically detects
prompt-injection paths - untrusted input → LLM → dangerous sink - in Python
and JavaScript/TypeScript, in CI, before they ship.

```
untrusted input  →  LLM  →  exec / shell / raw SQL / URL fetch   (no sanitizer)   ⇒  finding
```

## Where to go

| Document | What it covers | Read it when |
|---|---|---|
| [Getting started](getting-started.md) | Install, first scan, reading a finding, exit codes | You have 5 minutes |
| [End-to-end tutorial](tutorial.md) | A full workflow on a sample app: scan → understand → fix → verify → baseline → CI → library mode → JS | You're adopting Palisade on a real project |
| [Architecture](architecture.md) | Frontends → taint IR → engine → rules; how a finding is born; the precision philosophy; the safety contract | You're contributing, or evaluating how it works |
| [CLI reference](cli-reference.md) | Every command, flag, exit code, config key, the JSON schema, the baseline format | You're wiring it into tooling |
| [Rules reference](rules-reference.md) | All five builtin rules in depth; pattern semantics; sanitizer tiers; writing custom rules | You're tuning or extending coverage |
| [For AI agents](agents.md) | A machine-oriented contract: exact commands, JSON parsing, pass/fail policy, remediation loop | You're an agent - or you're pointing one at Palisade |
| [Roadmap](roadmap.md) | Phases 0–6 (Measure → Remediate), the sequencing thesis, current status per phase | You want to know where this is going |
| [Proof scans](proof-scans.md) | Palisade vs. the real CVE repos - hits, misses, and what each miss taught the engine | You want the evidence |

Related, outside `docs/`:

- [`README.md`](../README.md) - the front page.
- [`examples/support-bot/`](../examples/support-bot/) - the tutorial's sample app.
- [`examples/vulnerable-app/`](../examples/vulnerable-app/) - the acceptance fixtures (every behavior claim in these docs is pinned by a test against this app).
- [`src/palisade_sec/rules/README.md`](../src/palisade_sec/rules/README.md) - the 5-minute "add a rule" guide.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) · [`CHANGELOG.md`](../CHANGELOG.md) · [`AGENTS.md`](../AGENTS.md) (repo-level agent instructions) · [`llms.txt`](../llms.txt)

## The one-paragraph mental model

Palisade parses your source (never executes it), lowers it into a
language-neutral taint IR, and propagates taint from **sources** (request
fields, CLI args, route params, library params) through **LLM call sites**
into **sinks** (`exec`, shells, raw SQL, URL fetches). A finding requires the
*complete* source → LLM → sink path with no real sanitizer in between -
that's why it stays quiet on constant prompts, parameterized queries, and
arg-list subprocess calls, and why a denylist or a cosmetic "sanitizer"
downgrades a finding instead of silencing it. Rules are YAML data; adding
coverage never requires engine changes.
