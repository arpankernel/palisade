# Getting started

Five minutes from zero to your first finding.

## Install

The offline core (`scan`, `map`, `baseline`, `fix`) needs no API key, no
account, and makes no network calls. Python ≥ 3.11. (The optional judgment
layer, `audit` and `review`, calls an endpoint you configure - see
[Next steps](#next-steps).)

```bash
# one-shot, nothing installed permanently
uvx palisade-sec scan .

# or with pipx
pipx run palisade-sec scan .

# or as a project dev dependency
uv add --dev palisade-sec        # / pip install palisade-sec

# with the JavaScript/TypeScript frontend (tree-sitter)
uvx --from "palisade-sec[js]" palisade-sec scan .
pip install "palisade-sec[js]"
```

Python files are scanned out of the box. `.js`/`.mjs`/`.cjs`/`.jsx`/`.ts`/`.tsx`
are scanned when the `[js]` extra is installed - otherwise they're skipped
with a note telling you how to enable them.

## Your first scan

```bash
palisade-sec scan path/to/project
```

- **No findings** → a friendly success line, exit code `0`.
- **Findings** → each is printed with a full data-flow trace. Exit code is
  still `0` unless you pass `--ci`.

## Reading a finding

```
HIGH app.py:34  [PI-SQL] Prompt injection reaching raw SQL
  ↳ source: question = request.json["question"]  (app.py:24)
  ↳ llm:    resp = client.chat.completions.create(  (app.py:25)
  ↳ sink:   cur.execute(sql)  (app.py:34)
  No sanitizer on path.  Confidence: HIGH
  Attack: Crafted input steers the text-to-SQL model into emitting UNION-based
          exfiltration or destructive statements (DROP/DELETE), executed verbatim.
  Fix:    Execute model-generated SQL only through a read-only connection ...
  Refs:   https://owasp.org/...; CVE-2024-5565 (Vanna.ai); CVE-2024-5826 (Vanna.ai)
```

Every finding answers four questions:

1. **Where does untrusted input enter?** (`source`, with file:line)
2. **Where does it reach a model?** (`llm`)
3. **Where does the model's output do something dangerous?** (`sink` - the
   finding's headline location)
4. **What's the concrete attack, and what's the specific fix?**

Severity vs. confidence:

- **Severity** (`HIGH`/`MED`/`LOW`) is the rule's assessment of the sink. A
  HIGH finding downgraded to MED means a *partial* defense was found on the
  path (a denylist, a confirmation gate, or a sanitizer-in-name-only) - the
  path is still risky, and the output says exactly which defense and why it
  doesn't count.
- **Confidence** (`HIGH`/`MEDIUM`/`LOW`) reflects how direct the data-flow
  path is (how many function boundaries the taint crossed).

By default the terminal shows HIGH findings plus any "risky" downgraded
findings; `--all` shows everything (e.g. the advisory `PI-HTTP` rule).

## Gate your CI

```bash
palisade-sec baseline .          # once - fingerprints existing findings
git add .palisade/baseline.json

# in CI:
palisade-sec scan . --ci --baseline .palisade/baseline.json
```

`--ci` exits `1` only when a **new HIGH** finding appears. Fingerprints are
line-number independent, so refactors don't churn the baseline. GitHub
Actions example:

```yaml
- uses: astral-sh/setup-uv@v5
- run: uvx palisade-sec scan . --ci --baseline .palisade/baseline.json
```

## Next steps

- The [end-to-end tutorial](tutorial.md) walks a realistic app from first
  scan to a fixed, CI-gated state - including `palisade-sec fix`.
- Auditing a **library** rather than an app? See library mode
  (`--assume-params-untrusted`) in the [CLI reference](cli-reference.md).
- Wiring an **AI agent** to run Palisade? Start at [agents.md](agents.md).
- Want more than taint paths? `palisade-sec map` inventories your AI surface
  (offline), and `palisade-sec audit` / `review` add an optional judgment layer
  over an endpoint you set in `.env` (TypeSafe or any OpenAI-compatible). Setup
  and the per-command key table are in the
  [judgment layer guide](judgment-layer.md).
