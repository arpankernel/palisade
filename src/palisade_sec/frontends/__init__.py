"""Language frontends. Each lowers source code into the normalized taint IR.

Python (stdlib `ast`) is the reference frontend; JS/TS (tree-sitter, optional
`[js]` extra) and Jupyter notebooks (reassembled and delegated to Python)
plug in here with zero engine changes.
"""

from palisade_sec.frontends.ast_python import PythonFrontend
from palisade_sec.frontends.notebook import NotebookFrontend

__all__ = ["PythonFrontend", "NotebookFrontend"]
