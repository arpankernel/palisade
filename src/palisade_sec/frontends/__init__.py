"""Language frontends. Each lowers source code into the normalized taint IR.

v1 ships the Python frontend (stdlib `ast`). Future frontends (JS/TS/Go via
tree-sitter) plug in here with zero engine changes.
"""

from palisade_sec.frontends.ast_python import PythonFrontend

__all__ = ["PythonFrontend"]
