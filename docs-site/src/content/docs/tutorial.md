---
title: "End-to-end tutorial"
description: "Scan → understand → fix → verify → baseline → CI on a real sample app."
---

This is the full workflow on a realistic sample project: **scan → understand
→ fix → verify the fix → baseline the rest → gate CI**, plus the library-mode
and JavaScript variants. Every command output shown here is real (long
lines wrapped, and trimmed where marked `...`) - the sample app ships in the
repo at [`examples/support-bot/`](https://github.com/arpankernel/palisade/tree/main/examples/support-bot/). The fix steps
edit `app.py`, so run them on a copy.

## 0. The scenario

Your team shipped **SupportPilot**, a small Flask support bot with three
LLM-powered features:

- `POST /ask` - text-to-SQL over the orders database
- `POST /diagnose` - runs a shell diagnostic command the model suggests
- `POST /report` - generates and runs a small Python report snippet

`app.py` (abridged - full file in `examples/support-bot/`):

```python
@app.route("/ask", methods=["POST"])
def ask():
    question = request.json["question"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": "Translate the question into one SQL query."},
            {"role": "user", "content": question},
        ],
    )
    sql = resp.choices[0].message.content
    cur = get_db().cursor()
    cur.execute(sql)
    return jsonify(rows=cur.fetchall())

@app.route("/diagnose", methods=["POST"])
def diagnose():
    symptom = request.json["symptom"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"One shell command to diagnose: {symptom}"}],
    )
    command = resp.choices[0].message.content
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    return jsonify(output=output.stdout)

@app.route("/report", methods=["POST"])
def report():
    spec = request.json["spec"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Write Python that prints a report for: {spec}"}],
    )
    code = resp.choices[0].message.content
    exec(code)
    return jsonify(status="done")
```

Each feature works. Each one is also a textbook prompt-injection
vulnerability - the same shapes behind real CVEs (Vanna.ai CVE-2024-5565,
PandasAI CVE-2024-12366, LangChain PAL CVE-2023-36258).

## 1. First scan

```bash
uvx palisade-sec scan examples/support-bot
```

```
HIGH app.py:33  [PI-SQL] Prompt injection reaching raw SQL
  ↳ source: question = request.json["question"]  (app.py:23)
  ↳ llm:    resp = client.chat.completions.create(  (app.py:24)
  ↳ sink:   cur.execute(sql)  (app.py:33)
  No sanitizer on path.  Confidence: HIGH
  ...

HIGH app.py:48  [PI-SHELL] Prompt injection reaching an OS command
  ↳ source: symptom = request.json["symptom"]  (app.py:40)
  ↳ llm:    resp = client.chat.completions.create(  (app.py:41)
  ↳ sink:   output = subprocess.run(command, shell=True, capture_output=True,
            text=True)  (app.py:48)
  No sanitizer on path.  Confidence: HIGH
  ...

HIGH app.py:63  [PI-EXEC] Prompt injection reaching code execution
  ↳ source: spec = request.json["spec"]  (app.py:55)
  ↳ llm:    resp = client.chat.completions.create(  (app.py:56)
  ↳ sink:   exec(code)  # noqa: S102 - the tutorial fixes this one step by step
            (app.py:63)
  No sanitizer on path.  Confidence: HIGH
  ...

Found 3 high finding(s) in 2 file(s).
```

Three findings, one per feature, each with the complete data-flow trace.
Note what Palisade did **not** flag: the `client.chat.completions.create`
calls themselves (calling an LLM is not a bug), `jsonify(...)` returns, and
`get_db()` - no complete source→LLM→sink path, no noise.

## 2. Triage with machine-readable output

For tooling (or an AI agent), use JSON - the schema is stable and versioned
(see the [CLI reference](/palisade/docs/cli-reference/#json-schema)):

```bash
palisade-sec scan examples/support-bot --json | jq -c '.findings[] | {rule, file, line, severity}'
```

```json
{"rule":"PI-SQL","file":"app.py","line":33,"severity":"high"}
{"rule":"PI-SHELL","file":"app.py","line":48,"severity":"high"}
{"rule":"PI-EXEC","file":"app.py","line":63,"severity":"high"}
```

## 3. Get remediation templates

`fix` writes a remediation plan - for each finding, a guardrail tailored to
the rule *plus a pytest asserting the guardrail blocks the canonical attack*.
It's deterministic, offline, and never modifies your code:

```bash
palisade-sec fix examples/support-bot
```

```
remediation plan for 3 finding(s) written to palisade-fixes.md - each guardrail
ships with a regression test; adapt the allowlists, then add the tests to your
suite.
```

The plan is written to the current directory.

## 4. Fix the worst one first: `/report` (PI-EXEC)

The plan's PI-EXEC guardrail is an **AST allowlist** - the only defense shape
that has held up where denylists and confirmation gates failed (LangChain
PAL, Open Interpreter). Add it near the top of `app.py`:

```python
import ast

ALLOWED_NODES = (
    ast.Module, ast.Expr, ast.Call, ast.Name, ast.Load, ast.Constant,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.JoinedStr,
    ast.FormattedValue,
)


def validate_report_code(code: str) -> str:
    """Strict AST allowlist: print-and-arithmetic only, or reject."""
    for node in ast.walk(ast.parse(code)):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError(f"disallowed construct: {type(node).__name__}")
        if isinstance(node, ast.Name) and node.id != "print":
            raise ValueError(f"disallowed name: {node.id}")
    return code
```

and at the sink:

```python
    code = validate_report_code(resp.choices[0].message.content)
    exec(code, {"__builtins__": {"print": print}})
```

Add the plan's regression test to your suite - it's the part you shouldn't
skip:

```python
def test_guardrail_blocks_injected_code():
    with pytest.raises(ValueError):
        validate_report_code("__import__('os').system('id')")

def test_guardrail_allows_expected_code():
    assert validate_report_code("print(1 + 2)") == "print(1 + 2)"
```

### Verify the fix

```bash
palisade-sec scan .
```

```
HIGH app.py:51  [PI-SQL] Prompt injection reaching raw SQL
  ...
HIGH app.py:66  [PI-SHELL] Prompt injection reaching an OS command
  ...

Found 2 high finding(s) in 2 file(s).
```

PI-EXEC is gone (the other two moved down because the validator was added
above them).

Two things to notice about *why* the finding cleared:

- Palisade didn't just match the name `validate_report_code`. It resolved
  the function and **verified its body has an allowlist shape**: here, every
  node of the parsed code checked against a fixed set of allowed node types.
  Only allowlist shapes silence a finding (a lookup in a fixed allowed set,
  an AST node-type allowlist, or a strict matcher like `re.fullmatch`). A
  cosmetic sanitizer - say, `code.replace("import os", "")` - is reported as
  **MED "unverified sanitizer"** instead. Vanna's `_sanitize_plotly_code`
  shipped CVE-2024-5565 through exactly that trap.
- If you had "fixed" it with a denylist (`if "import" in code: raise`), a
  length check, or an "are you sure?" prompt, Palisade would keep the finding
  at **MED "risky"** - deliberately, because each of those is bypassable.

## 5. Fix the other two the same way

**`/diagnose` (PI-SHELL)** - never hand model output to a shell. Parse it,
allowlist the executable, use an argument list:

```python
import shlex

ALLOWED_COMMANDS = {"ping", "dig", "traceroute", "uptime"}

    argv = shlex.split(command)
    if not argv or argv[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"executable not allowed: {argv[:1]}")
    output = subprocess.run(argv, capture_output=True, text=True, timeout=10)
```

`subprocess.run([...])` with an argument list and no `shell=True` is a
**safe sink shape**, so it is never flagged.

**`/ask` (PI-SQL)** - model-written SQL runs only if it parses as a single
`SELECT`. Use the guardrail from the `fix` plan as a function, on a read-only
connection, with user *values* still parameterized:

```python
import sqlglot
from sqlglot import exp


def validate_generated_sql(sql: str) -> str:
    """Allow one SELECT statement, nothing else (the `fix` plan's guardrail)."""
    statements = sqlglot.parse(sql)
    if len(statements) != 1 or not isinstance(statements[0], exp.Select):
        raise ValueError("only a single SELECT is allowed")
    return sql

    sql = validate_generated_sql(resp.choices[0].message.content)
    cur.execute(sql)                      # read-only connection
# and for user-supplied values, always:
cur.execute("SELECT * FROM orders WHERE id = ?", (order_id,))   # never flagged
```

Keep the check in a named function. Palisade verifies sanitizer *functions*
(the parsed statement checked against an allowed statement type is an
allowlist shape); the same check written inline in the route is not
recognized, and the finding stays.

Rescan with both applied:

```
✓ No LLM injection paths found. (2 file(s) scanned)
```

## 6. Adopt on a real codebase: baseline + CI

On a real project you may not fix everything today. The baseline lets you
**stop the bleeding now** and burn down existing debt on your schedule:

```bash
palisade-sec baseline .                 # writes .palisade/baseline.json
git add .palisade/baseline.json && git commit -m "palisade baseline"
```

CI then fails only on **new** HIGH findings:

```bash
palisade-sec scan . --ci --baseline .palisade/baseline.json
```

Say you stopped after step 4, with two findings left. The two commands print:

```
baseline written to .palisade/baseline.json (2 finding(s) fingerprinted, 2 file(s) scanned)

✓ No new findings. (2 known finding(s) suppressed by baseline; 2 file(s) scanned)
```

and the `--ci` run exits `0`. Paste a second copy of a baselined route and
the gate fails again: the baseline records how many occurrences you accepted,
so a copied vulnerability counts as new.

```yaml
# .github/workflows/security.yml
- uses: astral-sh/setup-uv@v5
- run: uvx palisade-sec scan . --ci --baseline .palisade/baseline.json
```

Fingerprints are `rule + files + normalized code`, not line numbers - pure
refactors don't churn the baseline. When you fix a baselined finding, the
scan notes the stale entry; re-run `palisade-sec baseline` to refresh.

Want a shareable writeup for the security review? `--report` writes
`palisade-report.md` - a mini threat model grouped by severity with every
trace, fix, and CVE reference.

## 7. Variant: auditing a library

Apps read untrusted input from `request.*`. A **library** has no visible
caller - its public parameters *are* the untrusted world. Library mode
treats them as sources:

```bash
palisade-sec scan path/to/library --assume-params-untrusted
```

Library mode changes what counts as a source, and so which path a finding
reports. On vanna v0.5.5, Palisade's builtin rules flag the actual
CVE-2024-5565 sink (`base.py:1998`, `ask(question)` → `submit_prompt` →
`exec`) and nothing else in the repo, with or without library mode, as a MED
"risky" finding because of Vanna's cosmetic `_sanitize_plotly_code`. Without
the flag, the source is the `input()` call `ask` falls back to when no
question is passed:

```
MED  src/vanna/base/base.py:1998  [PI-FRAMEWORK-EXEC] Prompt injection via a framework LLM wrapper reaching code execution  (risky: partial defense only)
  ↳ source: question = input("Enter a question: ")  (src/vanna/base/base.py:1627)
  ↳ llm:    plotly_code = self.submit_prompt(message_log, kwargs=kwargs)  (src/vanna/base/base.py:706)
  ↳ sink:   exec(plotly_code, globals(), ldict)  (src/vanna/base/base.py:1998)
  ...
```

With `--assume-params-untrusted`, the source becomes the public `ask()`
parameter itself (`source: def ask(  (src/vanna/base/base.py:1594)`), which
is the entry point a library's callers actually use.
See [proof-scans.md](/palisade/docs/proof-scans/).

## 8. Variant: the same bugs in JavaScript/TypeScript

The same rules match JS - the SDK call paths are identical dotted paths:

```js
// routes.js - flagged PI-EXEC, same trace structure
app.post("/report", async (req, res) => {
  const resp = await client.chat.completions.create({
    messages: [{ role: "user", content: req.body.spec }],
  });
  eval(resp.choices[0].message.content);        // ← sink
});
```

```bash
uvx --from "palisade-sec[js]" palisade-sec scan .
```

Express `req.body`/`req.query` are sources; `eval`, `new Function`,
`vm.runIn*`, `child_process.exec`, and `pool.query(sql)` are sinks;
`["a","b"].includes(x)` guards are recognized enums. Parameterized
`pool.query(text, values)` is never flagged.

## Recap

| Step | Command | Outcome |
|---|---|---|
| Scan | `palisade-sec scan .` | 3 HIGH findings with full traces |
| Triage | `scan --json` | Stable schema for tooling/agents |
| Plan | `palisade-sec fix .` | Guardrail + regression test per finding |
| Fix | apply AST-allowlist / arg-list / SELECT-validator | PI-EXEC and PI-SHELL cleared on rescan |
| Adopt | `baseline` + `scan --ci --baseline` | CI fails only on *new* HIGHs |
| Extend | `--assume-params-untrusted`, `[js]` extra | Libraries and JS/TS covered |

The principle underneath every step: **a finding is a complete
source → LLM → sink path, and only a real, verifiable defense clears it.**
