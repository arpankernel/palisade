# Hardening audit

Audit-then-fix pass over Palisade against the self-safety and
production-readiness bar for a security tool. Scope: the code as it stood at
v0.3.2 (already well past the original vibe-coded v0.1.0 — the frontend/IR/
engine/rules split, pydantic rules, baseline, and JS frontend were already
in place). This pass targeted **self-security, resource-exhaustion,
type-safety, and the Phase-0 measurement gate**.

## STEP 1 — State of the codebase (audit)

| Dimension | Finding |
|---|---|
| Structure | Clean `frontends/ → ir/ → engine/ → rules/ → report/` split already present. `cli.py` (Typer), `scanner.py`, `baseline.py`, `fix.py`. |
| Architecture coupling | **No leakage** — the engine (`engine/analyzer.py`) operates only on `ir.*` types; `ast`/tree-sitter live solely in `frontends/`. The JS frontend proves this (added with zero engine changes). |
| Detection data-driven | Yes — sources, LLM signatures, sinks, sanitizers, partial defenses are YAML validated by `rules/schema.py`. Adding a rule needs no engine change. |
| Dependencies | Runtime: typer, rich, pydantic, pyyaml (+ tree-sitter behind `[js]` extra). Pinned via committed `uv.lock`. Minimal. |
| Python support | 3.11+ (`requires-python`), CI matrix 3.11–3.13. |
| Packaging | `pyproject.toml` with `palisade-sec` console script; `uvx`/`pipx run`/`pip` all verified; wheel + sdist published. |
| Tests | 104 → **112** passing; the example-app false-positive tests were already central. |
| Lint / types | ruff configured and clean; **mypy was absent** → added, now clean under a strict-ish config. |

Verdict going in: architecture and detection were sound; the gaps were in
**tool self-defense** (DoS, symlink escape, redaction), **type checking**,
and a **formal precision gate**. No blind rewrite warranted — incremental
fixes only.

## STEP 2 — Self-security (highest priority)

| Control | Before | After |
|---|---|---|
| SF-1 no code execution | True in practice (`ast.parse` only) but **unproven** | **Enforced by test**: a `sys.addaudithook` tripwire scans a hostile corpus and fails the build on any `exec` of target code, target import, `os.system`/subprocess, or socket connect (`tests/test_self_security.py`). |
| SF-2 no network | True | Asserted by the same audit-hook (no `socket.connect` during a scan). |
| SF-3 filesystem | Excludes + `.gitignore` honored | **Symlink-escape guard added**: a symlink resolving outside the scan root is skipped, not read. Writes already limited to `.palisade/` + report file. |
| Deserialization | `yaml.safe_load` already; pydantic-validated rules/config | Confirmed; no `pickle`/`marshal`/`yaml.load`. |
| DoS — file size | unbounded | `max_file_bytes` (default 2 MB), configurable; oversize files skipped with a warning. |
| DoS — recursion | `ast.parse` could stack-overflow on deep nesting | `RecursionError` caught in both frontends → skip-with-warning, never crash. |
| DoS — runtime | unbounded | `max_scan_seconds` soft budget; remaining files skipped with a warning. |
| Redaction | full source line in traces | Snippets capped at 200 chars — pathological/secret-bearing lines are truncated. |

Hostile fixture corpus added (`tests/fixtures/hostile/`): module-level side
effects + `SystemExit`, 6000-deep parens, deep nested lists, broken syntax,
null bytes, invalid UTF-8, a 2.4 MB file, and a secret-bearing 3000-char
line. All are skipped or safely analyzed; none execute or crash the run.

## STEP 3 — Scalability & architecture

Already clean (see Step 1). This pass added the **seams** for future scale
without building the full features (per roadmap Phase 3): a per-module
`content_hash` (sha256 of raw bytes) for future incremental/caching, files
processed independently, and deterministic output regardless of filesystem
order (pinned by `test_hostile_corpus_is_deterministic`). Inter-procedural
depth remains bounded (default 3) and configurable.

## STEP 4 — Robustness & correctness

- The one broad `except Exception` (JS frontend, guarding tree-sitter) is
  narrow in intent and documented; all target-file failures degrade to
  skip-with-warning.
- Findings already fingerprinted by `rule + normalized location + code hash`
  (line-shift resilient) — confirmed, pinned by baseline tests.
- False-positive guards from the PRD confirmed intact and tested; partial
  defenses and unverified sanitizers downgrade to MED, never suppress.
- Exit-code contract (0 clean/baselined, 1 new HIGH under `--ci`, 2 usage)
  confirmed; non-TTY disables color; `--json` schema versioned + documented.

## STEP 5 — Application hygiene

- **mypy** added (`[tool.mypy]`) and green over `src/palisade_sec`; fixed two
  genuine variable-reuse smells it surfaced in `engine/analyzer.py`.
- ruff lint + format clean; hostile fixtures excluded (they crash the Rust
  parser by design — itself a small proof the inputs are pathological).
- No stray `print` debugging in library code (user output goes through rich
  in `report/`).
- **SECURITY.md** added: private disclosure process, response targets, and
  the explicit definition of what counts as a vulnerability in a scanner.
- **Phase-0 precision harness** (`scripts/precision.py` + `corpus/manifest.yaml`):
  computes precision/recall/F1 against a labeled corpus and fails under
  threshold (0.90). Seed corpus scores 1.000/1.000; wired into CI and pinned
  by a test.
- CI now runs ruff + mypy + pytest + the self-security suite + the precision
  gate across Python 3.11–3.13, plus the two self-scan checks.

## STEP 6 — Verification

- `uv run pytest -q` → **112 passed**.
- `uv run mypy src/palisade_sec` → clean, 21 files.
- `uv run ruff check .` + `ruff format --check` → clean.
- `scripts/precision.py corpus/manifest.yaml` → precision 1.000, recall 1.000.
- Tool on itself (`scan src --ci`) → clean; on `examples/vulnerable-app` →
  4 HIGH + 1 MED, exit 1; on the hostile corpus → no execution, no crash.

## What remains (with severity)

- **[low] Python 3.9–3.10 support.** The prompt asked for a 3.9–3.13 matrix;
  the package targets 3.11+ (uses `X | Y` unions and `tomllib`). Lowering the
  floor is a deliberate product call, not a safety gap — deferred.
- **[low] Per-file hard timeout.** The current budget is a soft wall-clock
  cap across the run; a true per-file timeout needs process isolation
  (roadmap Phase 3). Recursion + size caps already prevent the common hangs.
- **[low] Full incremental scanning.** Seam present (`content_hash`); feature
  is Phase 3.
- **[none] Multi-language coupling.** No architectural coupling blocks new
  languages — the JS frontend already demonstrated zero-engine-change
  extension.
