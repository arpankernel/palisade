# vulnerable-app (fixtures)

A deliberately unsafe Flask app used as Palisade's acceptance fixtures.
**Do not deploy or copy patterns from this app.**

It contains, on purpose:
- 4 exploitable source → LLM → sink paths (exec, raw SQL, shell, and a
  multi-hop exec across three files) that must be flagged **HIGH**;
- 1 denylist-gated exec that must be flagged **MED "risky"** — partial
  defenses do not count as safe;
- 6 safe variants (sanitizer, arg-list subprocess, parameterized SQL,
  constant prompt, log-only output, enum-constrained output) that must stay
  **silent** — the false-positive tests are the most important in the repo.

`tests/test_example_app.py` pins every one of these expectations.
