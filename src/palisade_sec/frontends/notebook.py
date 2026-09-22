"""Jupyter notebook frontend: lowers `.ipynb` code cells into the normalized
taint IR by reassembling them into one Python source and delegating to
`PythonFrontend` - zero engine changes, same as every other frontend.

SAFETY: `.ipynb` is JSON. This module only ever calls `json.loads` on the raw
file text, then hands the reassembled *text* to `ast.parse` via
`PythonFrontend`. It never imports, execs, evals, or otherwise runs any code
or notebook metadata from the scanned project - the nbformat spec's
%-magics, cell outputs, and execution_count are read as inert strings/ints,
never interpreted. A pathologically nested notebook (deeply nested JSON
arrays/objects) is skipped like any other malformed input, never a crash:
`json.loads` raises `RecursionError` on those the same way `ast.parse` does
on deeply nested Python, and both are caught the same way (RB-3).

Reassembly, not per-cell parsing: a notebook is one execution unit - a name
bound in cell 1 is used in cell 3 (nbformat's whole reason to exist),
exactly like top-level statements in a .py file. Parsing each cell in
isolation would either miss that data flow entirely or require reinventing
cross-cell scope resolution the engine does not have a seam for.

Reporting: line numbers in a finding are lines in the *reassembled* source,
the same convention `jupyter nbconvert --to script` uses - a `# In[N]:`
marker line precedes each code cell, so opening the notebook and counting
code cells (or running nbconvert yourself) tells you exactly where a
reported line lives. Non-code cells (markdown, raw) contribute their marker
line only. IPython line/cell magics (`%matplotlib inline`, `!pip install`,
`%%time`) are blanked - they are not Python and `ast.parse` would reject
them outright - so a magic line reads as an empty statement, never dropped
from the line count.
"""

from __future__ import annotations

import json

from palisade_sec import ir
from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend


def _parse_notebook_json(notebook_text: str) -> dict | None:
    """Parse `.ipynb` JSON into the notebook document dict, or None if the
    text is not a notebook this frontend can read at all (malformed JSON,
    pathological nesting, or not a `{"cells": [...]}` shape)."""
    try:
        doc = json.loads(notebook_text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("cells"), list):
        return None
    return doc


def _cell_source(cell: dict) -> str:
    """A cell's `source` is either a single string or nbformat's list-of-lines
    form; either way, non-string entries (malformed notebooks) are skipped
    rather than crashing the scan."""
    src = cell.get("source", "")
    if isinstance(src, list):
        return "".join(s for s in src if isinstance(s, str))
    if isinstance(src, str):
        return src
    return ""


def _is_magic_or_shell(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("%") or stripped.startswith("!")


def _reassemble_doc(doc: dict) -> str:
    """`nbconvert --to script`-style reassembly: a `# In[N]:` marker line
    before each cell, so a reported line number is traceable back to a cell
    by counting markers."""
    lines: list[str] = []
    for idx, cell in enumerate(doc["cells"]):
        if not isinstance(cell, dict):
            continue
        lines.append(f"# In[{idx}]:")
        if cell.get("cell_type") != "code":
            continue
        for line in _cell_source(cell).splitlines():
            lines.append("" if _is_magic_or_shell(line) else line)
    return "\n".join(lines)


def reassemble(notebook_text: str) -> str | None:
    """Reassemble a notebook's cells into one Python source. Returns None if
    the text is not a notebook this frontend can read - the caller reports
    that as a ParseFailure, never a crash."""
    doc = _parse_notebook_json(notebook_text)
    return None if doc is None else _reassemble_doc(doc)


def _kernel_language(doc: dict) -> str | None:
    metadata = doc.get("metadata", {})
    if not isinstance(metadata, dict):
        return None
    lang_info = metadata.get("language_info", {})
    if isinstance(lang_info, dict):
        name = lang_info.get("name")
        if isinstance(name, str):
            return name
    kernelspec = metadata.get("kernelspec", {})
    if isinstance(kernelspec, dict):
        language = kernelspec.get("language")
        if isinstance(language, str):
            return language
    return None


class NotebookFrontend:
    """Lowers one `.ipynb` file at a time by reassembling its code cells and
    delegating to `PythonFrontend`. Non-Python-kernel notebooks (metadata
    `language_info.name` other than `python`) are reported as a
    ParseFailure - reassembled R/Julia/etc. source would not parse as
    Python anyway, and guessing at another language's IR is out of scope."""

    name = "jupyter"
    extensions = (".ipynb",)

    def lower_file(self, path: str, rel_path: str, source: str) -> ir.Module | ParseFailure:
        doc = _parse_notebook_json(source)
        if doc is None:
            return ParseFailure(path=path, reason="not a readable Jupyter notebook (.ipynb)")
        lang = _kernel_language(doc)
        if lang is not None and lang != "python":
            return ParseFailure(
                path=path, reason=f"notebook kernel language is {lang!r}, not python"
            )
        combined = _reassemble_doc(doc)
        return PythonFrontend().lower_file(path, rel_path, combined)
