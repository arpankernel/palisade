"""Normalized, language-agnostic taint IR.

Frontends (one per language) lower source code into this IR. The engine
operates *only* on the IR - it never sees a language-specific AST.
"""

from palisade_sec.ir.model import (
    Assign,
    Call,
    Collection,
    Const,
    Expr,
    ExprStmt,
    ForLoop,
    FuncDef,
    IfBranch,
    Loc,
    Member,
    Module,
    Return,
    Stmt,
    StrJoin,
    TryBlock,
    Unknown,
    VarRef,
    WhileLoop,
    WithBlock,
)

__all__ = [
    "Assign",
    "Call",
    "Collection",
    "Const",
    "Expr",
    "ExprStmt",
    "ForLoop",
    "FuncDef",
    "IfBranch",
    "Loc",
    "Member",
    "Module",
    "Return",
    "Stmt",
    "StrJoin",
    "TryBlock",
    "Unknown",
    "VarRef",
    "WhileLoop",
    "WithBlock",
]
