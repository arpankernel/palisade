# AGENTS.md - instructions for AI agents working on this repository

Two distinct audiences; make sure you're the right one:

- **Using Palisade to scan someone's codebase?** → read
  [`docs/agents.md`](docs/agents.md) (invocation contract, JSON parsing,
  remediation rules). This file is not for you.
- **Modifying Palisade itself?** → this file.

## Build, test, verify

```bash
uv sync                                   # deps (dev group includes tree-sitter)
uv run pytest -q                          # full suite - must stay green
uv run ruff check . && uv run ruff format --check src tests scripts corpus
uv run mypy src/palisade_sec              # must stay clean
uv run pytest tests/test_self_security.py # SF-1/2/3 tripwire over hostile corpus
uv run python scripts/precision.py corpus/manifest.yaml   # fast fixture precision gate
uv run pytest tests/test_fp_regressions.py # false-positive corpus - must stay silent

# the pinned third-party benchmark (network, gigabytes, scheduled in CI):
uv run python corpus/fetch.py                            # clone + pin the corpus
uv run python scripts/precision.py corpus/repos.yaml --repos --triage
uv run palisade-sec scan examples/vulnerable-app --all   # 4 high + 1 med, always
uv run palisade-sec scan src --ci         # self-scan - must exit 0
uv run python scripts/make_demo.py        # regenerate docs/demo.svg after output changes
```

CI (`.github/workflows/ci.yml`) runs all of the above on Python
3.11/3.12/3.13 and additionally asserts the example app **fails** `--ci`.

## Layout

```
src/palisade_sec/
├── frontends/     # language → IR lowering (ast_python.py, tree_sitter_js.py)
├── ir/            # normalized taint IR - language-neutral, no ast/tree-sitter types
├── engine/        # analyzer.py (taint propagation), findings.py, taint.py
├── rules/         # builtin YAML rules + pydantic schema + loader
├── report/        # terminal / json / markdown emitters
├── scanner.py     # discovery, config, frontend dispatch
├── baseline.py    # fingerprints & diffing
├── fix.py         # remediation-plan templates
└── cli.py         # Typer CLI
examples/vulnerable-app/   # acceptance fixtures - tests pin exact findings
examples/support-bot/      # docs/tutorial.md sample app
tests/                     # ~112 tests; FP tests are the highest-value ones
tests/fixtures/hostile/    # adversarial corpus for the self-security suite
tests/fixtures/regressions/ # false-positive cases that must stay silent, forever
corpus/                    # Phase-0 benchmark: fixture manifest + pinned repos
corpus/repos/              # the clones themselves (gitignored, ~2.5 GB)
docs/                      # markdown source of record for the docs
docs-site/                 # Astro + Starlight site that renders docs/
website/                   # marketing site (static, zero-dependency)
```

### Website & docs site

`docs/*.md` is the **source of record**. `docs-site/` renders it with Astro +
Starlight; the files under `docs-site/src/content/docs/` are generated copies
carrying frontmatter - when you change a doc, update `docs/` and mirror it
there (same filename, keep the frontmatter block).

```bash
cd docs-site && npm install && npm run dev     # docs at localhost:4321
cd docs-site && npm run build                  # -> docs-site/dist
```

The marketing site is a single static `website/index.html`: no build step and
no external JS - animations are hand-rolled and JS-gated, so the page renders
fully with JavaScript disabled. CI (`.github/workflows/pages.yml`) assembles
both - marketing at `/`, docs at `/docs/` - and publishes to GitHub Pages.

## Invariants - violating any of these is a rejected change

1. **Precision over recall.** Any change that makes something new get
   flagged MUST ship a matching must-NOT-flag test. The example-app safe
   cases (`calc_safe`, `ping`, `lookup`, `nightly_report`, `chat`,
   `action`) must stay silent; `tests/test_example_app.py` pins the exact
   finding set (4 HIGH + 1 MED, nothing else).
2. **The engine touches only the IR.** Never import `ast` or tree-sitter
   types inside `engine/` or reference them in rules. Language specifics
   belong in `frontends/`.
3. **The scanner never executes scanned code.** Parse text only. No
   `exec`/`eval`/`import` of target code, no network calls in `scan`, no
   telemetry. `test_sf_never_executes_scanned_code` enforces this - extend
   it if you add I/O.
4. **Partial defenses never suppress.** Denylists, confirmation gates, and
   unverified (name-only) sanitizers downgrade to MED - they must never
   silence a finding.
5. **Rules are data.** New coverage = YAML + fixtures, zero engine changes.
   A rule PR without a must-flag fixture AND a same-shaped must-stay-silent
   fixture is incomplete.
6. **Stable interfaces:** the `--json` schema (`schema_version: 1` - bump it
   for breaking changes and document in `docs/cli-reference.md`), exit codes
   (0/1/2), and baseline fingerprint semantics (line-shift resilient).
   Terminal output is NOT an interface; anything printed through rich must
   escape dynamic text (`rich.markup.escape`).
7. **Determinism.** Findings, JSON, and baseline files are sorted; no
   wall-clock or randomness in scan results.
9. **Precision only ratchets upward.** Every reported false positive
   becomes a permanent fixture in `tests/fixtures/regressions/`. Never
   silence one by weakening an assertion, and never delete a regression
   fixture unless the code it represents turns out to be genuinely
   dangerous - which belongs in the commit message.
10. **Suppressions stay loud.** `# palisade: ignore[RULE]` must keep being
   counted, attributable and stale-checked. A silent suppression mechanism
   is how a vulnerability quietly returns.

8. **Self-defense is a hard gate.** The audit-hook suite in
   `tests/test_self_security.py` must stay green: no exec/import of target
   code, no subprocess, no sockets during a scan; symlinks escaping the scan
   root are skipped; oversized/deeply-nested/malformed files are skipped with
   a warning, never crash. Resource caps (`max_file_bytes`,
   `max_scan_seconds`) and 200-char snippet redaction are part of the
   contract - see `SECURITY.md` and `HARDENING-AUDIT.md`.

## Conventions

- Python ≥ 3.11, `ruff` (line length 100) for lint + format; match existing
  comment density and docstring style.
- Version lives in BOTH `pyproject.toml` and `src/palisade_sec/__init__.py`;
  update `CHANGELOG.md` with every user-visible change.
- Docs claims must be real: tutorial/README outputs are captured from actual
  runs - if you change output formats, re-run the commands and update
  `docs/` plus `scripts/make_demo.py`'s SVG.
- Releases: tag `vX.Y.Z`, GitHub release, `uv build && uv publish`
  (maintainer's PyPI token - never commit or echo it).

## Where to add things

| Task | Touch |
|---|---|
| New framework/provider coverage | `src/palisade_sec/rules/*.yaml` + fixture tests |
| New source/sink *shape* (kwargs, arg positions) | `rules/schema.py` + `engine/analyzer.py` sink/source handling + tests |
| New language | new `frontends/<lang>.py` emitting the IR + scanner dispatch + a `tests/test_<lang>_frontend.py` mirroring `test_js_frontend.py` - zero engine edits expected |
| New output format (e.g. SARIF) | `report/` + CLI flag + schema doc |
| A reported false positive | a fixture in `tests/fixtures/regressions/`, then fix the rule or engine until it stays silent |
| New benchmark repo | an entry in `corpus/repos.yaml` + `corpus/fetch.py` to pin it |
| Engine precision change | `engine/analyzer.py` + BOTH FN and FP tests + verify example-app pins still hold |
