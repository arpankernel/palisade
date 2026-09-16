"""Deliberately vulnerable Flask app - Palisade's acceptance fixtures.

DO NOT DEPLOY. Every route here is either a real LLM prompt-injection
vulnerability (must be flagged), a safe variant (must stay silent), or a
partially-defended variant (must be flagged MED "risky").
"""

import subprocess

from flask import Flask, jsonify, request
from openai import OpenAI

from db import get_db
from agent_pipeline import run_agent
from guards import is_blocked_code, validate_code

app = Flask(__name__)
client = OpenAI()

MODEL = "gpt-4o-mini"


# ---------------------------------------------------------------------------
# VULNERABLE - must be flagged HIGH
# ---------------------------------------------------------------------------


@app.route("/calc", methods=["POST"])
def calc():
    """VULN 1 (PI-EXEC, PandasAI-style): NL question -> LLM Python -> exec."""
    question = request.json["question"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": "Reply with Python code only."},
            {"role": "user", "content": f"Write Python that answers: {question}"},
        ],
    )
    code = resp.choices[0].message.content
    exec(code)  # noqa: S102 - the vulnerability under test
    return jsonify(status="done")


@app.route("/ask-db")
def ask_db():
    """VULN 2 (PI-SQL, Vanna-style): text-to-SQL -> raw execute."""
    question = request.args.get("q", "")
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Write a SQL query for: {question}"}],
    )
    sql = resp.choices[0].message.content
    cur = get_db().cursor()
    cur.execute(sql)
    return jsonify(rows=cur.fetchall())


@app.route("/ops", methods=["POST"])
def ops():
    """VULN 3 (PI-SHELL): task description -> LLM shell command -> shell."""
    task = request.form["task"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Give me one shell command to: {task}"}],
    )
    command = resp.choices[0].message.content
    subprocess.run(command, shell=True)
    return jsonify(status="ran")


@app.route("/agent", methods=["POST"])
def agent():
    """VULN 4 (PI-EXEC, multi-hop): source here, LLM in llm_utils.py,
    sink in executor.py - three functions across three files."""
    goal = request.json["goal"]
    result = run_agent(goal)
    return jsonify(result=result)


# ---------------------------------------------------------------------------
# PARTIAL DEFENSE - must be flagged MED "risky" (not HIGH, not silent)
# ---------------------------------------------------------------------------


@app.route("/calc-guarded", methods=["POST"])
def calc_guarded():
    """A denylist gate before exec, LangChain-PAL-style. Real CVEs were
    exploited despite exactly this defense."""
    question = request.json["question"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Write Python that answers: {question}"}],
    )
    code = resp.choices[0].message.content
    if is_blocked_code(code):
        return jsonify(error="blocked"), 400
    exec(code)  # noqa: S102 - still exploitable: denylists are bypassable
    return jsonify(status="done")


# ---------------------------------------------------------------------------
# SAFE - must NOT be flagged
# ---------------------------------------------------------------------------


@app.route("/calc-safe", methods=["POST"])
def calc_safe():
    """SAFE (a): same shape as /calc, but the code is validated against a
    strict AST allowlist before running."""
    question = request.json["question"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Write Python that answers: {question}"}],
    )
    code = validate_code(resp.choices[0].message.content)
    exec(code)  # noqa: S102 - sanitized above
    return jsonify(status="done")


@app.route("/ping", methods=["POST"])
def ping():
    """SAFE (b): LLM output used as ONE ARGUMENT in an arg-list subprocess
    call - no shell, no injection into a command line."""
    where = request.json["where"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Hostname most relevant to: {where}"}],
    )
    host = resp.choices[0].message.content.strip()
    subprocess.run(["ping", "-c", "1", host], check=False)
    return jsonify(status="ok")


@app.route("/lookup", methods=["POST"])
def lookup():
    """SAFE (c): LLM output bound via a PARAMETERIZED query."""
    description = request.json["description"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Product name for: {description}"}],
    )
    product = resp.choices[0].message.content
    cur = get_db().cursor()
    cur.execute("SELECT * FROM products WHERE name = ?", (product,))
    return jsonify(rows=cur.fetchall())


def nightly_report():
    """SAFE (d): constant developer prompt - no untrusted source at all."""
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": "Write Python that prints yesterday's date."}],
    )
    code = resp.choices[0].message.content
    exec(code)  # noqa: S102 - developer-controlled prompt, not user input


@app.route("/chat", methods=["POST"])
def chat():
    """SAFE (e): LLM output is only logged and returned - never executed."""
    message = request.json["message"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": message}],
    )
    answer = resp.choices[0].message.content
    app.logger.info("chat answer: %s", answer)
    print(answer)
    return jsonify(answer=answer)


@app.route("/action", methods=["POST"])
def action():
    """SAFE (f): LLM output constrained to a literal enum before the sink."""
    wish = request.json["wish"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"One of list|status|uptime for: {wish}"}],
    )
    verb = resp.choices[0].message.content.strip()
    if verb in ("list", "status", "uptime"):
        subprocess.run(verb, shell=True)
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(debug=True)
