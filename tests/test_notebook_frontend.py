"""Jupyter notebook frontend: reassembles .ipynb code cells into Python
source and delegates to PythonFrontend - same engine, zero engine changes,
mirroring test_js_frontend.py's role for the JS/TS frontend."""

from __future__ import annotations

import json
import textwrap

import pytest

from palisade_sec.frontends.notebook import NotebookFrontend, reassemble
from palisade_sec.scanner import run_scan


def _notebook(*cells: tuple[str, str], language: str = "python") -> str:
    """Build minimal nbformat JSON from (cell_type, source) pairs."""
    doc = {
        "cells": [
            {
                "cell_type": kind,
                "execution_count": None,
                "metadata": {},
                "source": textwrap.dedent(src).strip("\n").splitlines(keepends=True),
                "outputs": [] if kind == "code" else [],
            }
            for kind, src in cells
        ],
        "metadata": {"language_info": {"name": language}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return json.dumps(doc)


def _scan(tmp_path, name: str, notebook_json: str):
    (tmp_path / name).write_text(notebook_json, encoding="utf-8")
    return run_scan(tmp_path)


# ---------------------------------------------------------------------------
# end to end: must flag / must stay silent, through the real scan pipeline
# ---------------------------------------------------------------------------


def test_injection_split_across_cells_is_flagged(tmp_path):
    # The realistic notebook shape: setup in one cell, the vulnerable call in
    # another - reassembly (not per-cell parsing) is what makes this visible.
    nb = _notebook(
        (
            "code",
            """
            %matplotlib inline
            import openai
            from flask import request
            client = openai.OpenAI()
            """,
        ),
        (
            "markdown",
            "# Ask the model to write some code",
        ),
        (
            "code",
            """
            def ask():
                question = request.json["question"]
                resp = client.chat.completions.create(
                    model="gpt-4", messages=[{"role": "user", "content": question}]
                )
                code = resp.choices[0].message.content
                exec(code)
            """,
        ),
    )
    res = _scan(tmp_path, "vuln.ipynb", nb)
    assert res.skipped == [], res.skipped
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    f = res.findings[0]
    assert f.severity == "high"
    assert f.source.file == "vuln.ipynb"
    assert f.sink.snippet == "exec(code)"


def test_safe_notebook_is_silent(tmp_path):
    nb = _notebook(("code", "x = 1 + 1\nprint(x)\n"))
    res = _scan(tmp_path, "safe.ipynb", nb)
    assert res.skipped == []
    assert res.findings == []


def test_markdown_only_notebook_is_silent(tmp_path):
    nb = _notebook(("markdown", "# just notes, no code"))
    res = _scan(tmp_path, "notes.ipynb", nb)
    assert res.skipped == []
    assert res.findings == []


# ---------------------------------------------------------------------------
# resilience: malformed / non-Python input never crashes the scan
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content, reason_contains",
    [
        pytest.param("not json at all {{{", "not a readable Jupyter notebook", id="invalid-json"),
        pytest.param("[]", "not a readable Jupyter notebook", id="json-not-an-object"),
        pytest.param('{"nbformat": 4}', "not a readable Jupyter notebook", id="missing-cells"),
        pytest.param(
            json.dumps({"cells": [{"cell_type": "code", "source": "x = 1 +"}]}),
            None,  # a real ast.parse SyntaxError, message not pinned here
            id="cell-body-is-invalid-python",
        ),
    ],
)
def test_malformed_notebook_is_skipped_not_crashed(tmp_path, content, reason_contains):
    res = _scan(tmp_path, "bad.ipynb", content)
    assert res.findings == []
    assert len(res.skipped) == 1
    if reason_contains:
        assert reason_contains in res.skipped[0]


def test_non_python_kernel_is_skipped(tmp_path):
    nb = _notebook(("code", "x <- 1 + 1"), language="R")
    res = _scan(tmp_path, "r_notebook.ipynb", nb)
    assert res.findings == []
    assert "not python" in res.skipped[0]


def test_magic_and_shell_lines_do_not_break_parsing(tmp_path):
    nb = _notebook(
        (
            "code",
            """
            !pip install openai
            %%time
            %env FOO=bar
            import openai
            """,
        )
    )
    res = _scan(tmp_path, "magics.ipynb", nb)
    assert res.skipped == [], res.skipped


# ---------------------------------------------------------------------------
# reassemble(): the pure text-transformation unit, independent of ast.parse
# ---------------------------------------------------------------------------


def test_reassemble_returns_none_for_non_notebook_text():
    assert reassemble("print('hello')") is None
    assert reassemble("{}") is None


def test_reassemble_inserts_a_marker_line_per_cell():
    nb = _notebook(("code", "a = 1"), ("code", "b = 2"))
    combined = reassemble(nb)
    assert combined is not None
    assert combined.count("# In[") == 2


def test_notebook_frontend_extensions_and_name():
    fe = NotebookFrontend()
    assert fe.extensions == (".ipynb",)
    assert fe.name == "jupyter"
