"""Defense helpers for the fixtures: one real sanitizer, one partial defense."""

import ast

ALLOWED_NODE_TYPES = (
    ast.Module,
    ast.Expr,
    ast.Call,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
)

BLOCKED_TOKENS = ["os.", "subprocess", "open(", "__import__", "eval(", "exec("]


def validate_code(code: str) -> str:
    """A real sanitizer: strict AST allowlist — anything outside a tiny
    arithmetic subset is rejected."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODE_TYPES):
            raise ValueError(f"disallowed construct: {type(node).__name__}")
    return code


def is_blocked_code(code: str) -> bool:
    """A PARTIAL defense: a denylist of scary substrings. Trivially
    bypassable (getattr tricks, encodings, aliasing) — real CVEs shipped
    with exactly this."""
    return any(token in code for token in BLOCKED_TOKENS)
