"""JS/TS frontend (tree-sitter): the multi-language architecture proof.
Same engine, same YAML rules - a new frontend, zero engine changes."""

import textwrap

import pytest

from palisade_sec.scanner import run_scan

tree_sitter = pytest.importorskip("tree_sitter")


def _scan(tmp_path, **files):
    for name, body in files.items():
        fname = name.replace("__", ".")  # app__js -> app.js, bot__ts -> bot.ts
        (tmp_path / fname).write_text(textwrap.dedent(body))
    res = run_scan(tmp_path)
    assert res.skipped == [], f"fixture must parse cleanly: {res.skipped}"
    return res


# ---------------------------------------------------------------------------
# must flag
# ---------------------------------------------------------------------------


def test_express_llm_eval_flagged(tmp_path):
    res = _scan(
        tmp_path,
        app__js="""
        import OpenAI from "openai";
        import express from "express";

        const app = express();
        const client = new OpenAI();

        app.post("/calc", async (req, res) => {
          const question = req.body.question;
          const resp = await client.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [{ role: "user", content: `Write JS for: ${question}` }],
          });
          const code = resp.choices[0].message.content;
          eval(code);
          res.json({ status: "done" });
        });
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    f = res.findings[0]
    assert f.severity == "high"
    assert f.source.detail == "req.body"


def test_child_process_exec_flagged(tmp_path):
    res = _scan(
        tmp_path,
        ops__js="""
        const { exec } = require("child_process");
        const OpenAI = require("openai");
        const client = new OpenAI();

        async function handleTask(req, res) {
          const task = req.body.task;
          const resp = await client.chat.completions.create({
            messages: [{ role: "user", content: task }],
          });
          const command = resp.choices[0].message.content;
          exec(command);
        }
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-SHELL"]


def test_text_to_sql_pool_query_flagged(tmp_path):
    res = _scan(
        tmp_path,
        db__js="""
        import OpenAI from "openai";
        import pg from "pg";

        const client = new OpenAI();
        const pool = new pg.Pool();

        export async function askDb(req, res) {
          const q = req.query.q;
          const resp = await client.chat.completions.create({
            messages: [{ role: "user", content: "SQL for: " + q }],
          });
          const sql = resp.choices[0].message.content;
          const rows = await pool.query(sql);
          res.json(rows);
        }
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-SQL"]


def test_typescript_new_function_flagged(tmp_path):
    res = _scan(
        tmp_path,
        agent__ts="""
        import OpenAI from "openai";
        const client = new OpenAI();

        export async function runAgent(req: any): Promise<void> {
          const goal: string = req.body.goal;
          const resp = await client.chat.completions.create({
            messages: [{ role: "user", content: goal }],
          });
          const code = resp.choices[0].message.content;
          const fn = new Function(code);
          fn();
        }
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    assert "Function" in res.findings[0].sink.detail


def test_anthropic_js_shape_flagged(tmp_path):
    res = _scan(
        tmp_path,
        bot__js="""
        import Anthropic from "@anthropic-ai/sdk";
        const anthropic = new Anthropic();

        export async function chat(req, res) {
          const msg = await anthropic.messages.create({
            model: "claude-sonnet-5",
            messages: [{ role: "user", content: req.body.message }],
          });
          eval(msg.content[0].text);
        }
        """,
    )
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]


# ---------------------------------------------------------------------------
# must NOT flag (precision carries over to JS)
# ---------------------------------------------------------------------------


def test_constant_prompt_silent_js(tmp_path):
    res = _scan(
        tmp_path,
        cron__js="""
        import OpenAI from "openai";
        const client = new OpenAI();

        export async function nightly() {
          const resp = await client.chat.completions.create({
            messages: [{ role: "user", content: "print today's date" }],
          });
          eval(resp.choices[0].message.content);
        }
        """,
    )
    assert res.findings == []


def test_parameterized_query_silent_js(tmp_path):
    res = _scan(
        tmp_path,
        db__js="""
        import OpenAI from "openai";
        const client = new OpenAI();

        export async function lookup(req, res, pool) {
          const resp = await client.chat.completions.create({
            messages: [{ role: "user", content: req.body.desc }],
          });
          const product = resp.choices[0].message.content;
          await pool.query("SELECT * FROM products WHERE name = $1", [product]);
        }
        """,
    )
    assert res.findings == []


def test_output_only_logged_silent_js(tmp_path):
    res = _scan(
        tmp_path,
        chat__js="""
        import OpenAI from "openai";
        const client = new OpenAI();

        export async function chat(req, res) {
          const resp = await client.chat.completions.create({
            messages: [{ role: "user", content: req.body.message }],
          });
          const answer = resp.choices[0].message.content;
          console.log(answer);
          res.json({ answer });
        }
        """,
    )
    assert res.findings == []


def test_enum_includes_guard_silent_js(tmp_path):
    res = _scan(
        tmp_path,
        action__js="""
        const { execSync } = require("child_process");
        import OpenAI from "openai";
        const client = new OpenAI();

        export async function action(req, res) {
          const resp = await client.chat.completions.create({
            messages: [{ role: "user", content: req.body.wish }],
          });
          const verb = resp.choices[0].message.content.trim();
          if (["uptime", "date"].includes(verb)) {
            execSync(verb);
          }
        }
        """,
    )
    assert res.findings == []


def test_mixed_project_python_and_js(tmp_path):
    """One scan covers both languages; per-language findings coexist."""
    res = _scan(
        tmp_path,
        app__js="""
        import OpenAI from "openai";
        const client = new OpenAI();
        export async function h(req, res) {
          const r = await client.chat.completions.create({
            messages: [{ role: "user", content: req.body.q }],
          });
          eval(r.choices[0].message.content);
        }
        """,
        app__py="""
        import os
        from flask import request
        from openai import OpenAI
        client = OpenAI()

        def handler():
            q = request.json["q"]
            resp = client.chat.completions.create(messages=[{"role": "user", "content": q}])
            os.system(resp.choices[0].message.content)
        """,
    )
    assert {(f.rule_id, f.sink.file) for f in res.findings} == {
        ("PI-EXEC", "app.js"),
        ("PI-SHELL", "app.py"),
    }
