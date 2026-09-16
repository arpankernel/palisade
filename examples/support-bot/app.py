"""SupportPilot — the docs tutorial sample app (deliberately vulnerable).

A tiny customer-support bot with three LLM-powered features. Each one wires
untrusted input through an LLM into a dangerous sink. Used by
docs/tutorial.md — DO NOT DEPLOY.
"""

import subprocess

from db import get_db
from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()

MODEL = "gpt-4o-mini"


@app.route("/ask", methods=["POST"])
def ask():
    """Feature 1: answer questions about order data (text-to-SQL)."""
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
    """Feature 2: run a diagnostic command suggested by the model."""
    symptom = request.json["symptom"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "user", "content": f"One shell command to diagnose: {symptom}"},
        ],
    )
    command = resp.choices[0].message.content
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    return jsonify(output=output.stdout)


@app.route("/report", methods=["POST"])
def report():
    """Feature 3: generate and run a small Python snippet for a custom report."""
    spec = request.json["spec"]
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "user", "content": f"Write Python that prints a report for: {spec}"},
        ],
    )
    code = resp.choices[0].message.content
    exec(code)  # noqa: S102 — the tutorial fixes this one step by step
    return jsonify(status="done")


if __name__ == "__main__":
    app.run(debug=True)
