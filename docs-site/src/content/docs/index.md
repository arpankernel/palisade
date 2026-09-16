---
template: splash
title: "Palisade"
description: "A linter for LLM security: prompt-injection paths caught in CI, before they ship."
hero:
  tagline: Catches untrusted input → LLM → exec / shell / SQL / fetch, in CI, before it ships.
  actions:
    - text: Get started
      link: ./getting-started/
      icon: right-arrow
    - text: View on GitHub
      link: https://github.com/arpankernel/palisade
      icon: external
      variant: minimal
---

**Palisade is a linter for LLM security**: it statically detects
prompt-injection paths - untrusted input → LLM → dangerous sink - in Python
and JavaScript/TypeScript, in CI, before they ship.

```
untrusted input  →  LLM  →  exec / shell / raw SQL / URL fetch   (no sanitizer)   ⇒  finding
```

## Where to go

| Document | What it covers | Read it when |
|---|---|---|
| [Getting started](../getting-started/) | Install, first scan, reading a finding, exit codes | You have 5 minutes |
| [End-to-end tutorial](../tutorial/) | A full workflow on a sample app: scan → understand → fix → verify → baseline → CI → library mode → JS | You're adopting Palisade on a real project |
| [Architecture](../architecture/) | Frontends → taint IR → engine → rules; how a finding is born; the precision philosophy; the safety contract | You're contributing, or evaluating how it works |
| [CLI reference](../cli-reference/) | Every command, flag, exit code, config key, the JSON schema, the baseline format | You're wiring it into tooling |
| [Rules reference](../rules-reference/) | All five builtin rules in depth; pattern semantics; sanitizer tiers; writing custom rules | You're tuning or extending coverage |
| [For AI agents](../agents/) | A machine-oriented contract: exact commands, JSON parsing, pass/fail policy, remediation loop | You're an agent - or you're pointing one at Palisade |
| [Roadmap](../roadmap/) | Phases 0–6 (Measure → Remediate), the sequencing thesis, current status per phase | You want to know where this is going |
| [Proof scans](../proof-scans/) | Palisade vs. the real CVE repos - hits, misses, and what each miss taught the engine | You want the evidence |

Related, outside `docs/`:

- [`README.md`](https://github.com/arpankernel/palisade/blob/main/README.md) - the front page.
- [`examples/support-bot/`](https://github.com/arpankernel/palisade/blob/main/examples/support-bot/) - the tutorial's sample app.
- [`examples/vulnerable-app/`](https://github.com/arpankernel/palisade/blob/main/examples/vulnerable-app/) - the acceptance fixtures (every behavior claim in these docs is pinned by a test against this app).
- [`src/palisade_sec/rules/README.md`](https://github.com/arpankernel/palisade/blob/main/src/palisade_sec/rules/README.md) - the 5-minute "add a rule" guide.
- [`CONTRIBUTING.md`](https://github.com/arpankernel/palisade/blob/main/CONTRIBUTING.md) · [`CHANGELOG.md`](https://github.com/arpankernel/palisade/blob/main/CHANGELOG.md) · [`AGENTS.md`](https://github.com/arpankernel/palisade/blob/main/AGENTS.md) (repo-level agent instructions) · [`llms.txt`](https://github.com/arpankernel/palisade/blob/main/llms.txt)

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
