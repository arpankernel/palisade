# Contributing to Palisade

Thanks for helping make LLM-security review as routine as running a linter.

## The fastest way to contribute: rules

Most coverage gaps are rule gaps, not engine gaps. Adding a framework's
sources/LLM signatures/sinks is a small YAML PR with no engine changes -
see [`src/palisade_sec/rules/README.md`](src/palisade_sec/rules/README.md)
for the 5-minute guide. Every rule PR needs two fixtures: one that must be
flagged, one same-shaped safe variant that must stay silent.

## Ground rules (from the design philosophy)

1. **Precision over recall.** A false positive is worse than a miss. If your
   change flags something new, it needs a matching must-NOT-flag test.
2. **Taint, not grep.** Findings require a complete source → LLM → sink path.
3. **The engine operates only on the IR.** Never leak Python `ast` types into
   `engine/` or rules; language specifics belong in `frontends/`.
4. **The tool never runs scanned code.** `ast.parse` only. No network calls
   in `scan`. Ever.
5. **Partial defenses (denylists, confirmation gates) downgrade to MED -
   they never suppress.** Real CVEs shipped with exactly those defenses.

## Dev setup

```bash
git clone https://github.com/arpankernel/palisade && cd palisade
uv sync
uv run pytest          # the example-app FP tests are the ones that gate merges
uv run ruff check .
uv run palisade-sec scan examples/vulnerable-app --all
```

## Project layout

```
src/palisade_sec/
├── frontends/   # language -> IR lowering (Python: stdlib ast)
├── ir/          # normalized taint IR (language-agnostic)
├── engine/      # taint propagation, sanitizer resolution, confidence
├── rules/       # YAML rules + pydantic schema (community entry point)
├── report/      # terminal / json / markdown emitters
├── baseline.py  # CI baseline (fail only on NEW findings)
└── cli.py       # Typer CLI
examples/vulnerable-app/   # the acceptance fixtures - deliberately unsafe
```

## Adding a language frontend (post-v1)

A frontend lowers source into `ir.Module` - see
`frontends/ast_python.py` for the reference implementation. If your frontend
emits correct IR, every existing rule and the whole engine work unchanged.
Open an issue first so we can coordinate on tree-sitter setup.

## Reporting vulnerabilities in Palisade itself

Email the maintainers privately rather than opening a public issue.
