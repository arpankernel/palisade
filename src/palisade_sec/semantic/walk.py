"""Shared IR traversal for the semantic layer.

Small, total over the node vocabulary in ir/model.py. Both the PROBE (tool
harvesting) and the MAP (AI-surface inventory) walk the IR the same way.
"""

from __future__ import annotations

from collections.abc import Iterator

from palisade_sec import ir


def iter_call_exprs(expr: ir.Expr | None) -> Iterator[ir.Call]:
    """Yield every Call reachable from an expression (including nested)."""
    if expr is None:
        return
    if isinstance(expr, ir.Call):
        yield expr
        for a in expr.args:
            yield from iter_call_exprs(a)
        for v in expr.kwargs.values():
            yield from iter_call_exprs(v)
        for s in expr.star_args:
            yield from iter_call_exprs(s)
        yield from iter_call_exprs(expr.receiver)
    elif isinstance(expr, ir.Member):
        yield from iter_call_exprs(expr.base)
    elif isinstance(expr, ir.StrJoin):
        for p in expr.parts:
            yield from iter_call_exprs(p)
    elif isinstance(expr, ir.Collection):
        for it in expr.items:
            yield from iter_call_exprs(it)
    elif isinstance(expr, ir.Unknown):
        for c in expr.children:
            yield from iter_call_exprs(c)


def iter_calls(stmts: list[ir.Stmt]) -> Iterator[ir.Call]:
    """Yield every Call reachable from a statement list (recursing bodies)."""
    for st in stmts:
        if isinstance(st, ir.Assign):
            yield from iter_call_exprs(st.value)
        elif isinstance(st, ir.ExprStmt):
            yield from iter_call_exprs(st.value)
        elif isinstance(st, ir.Return):
            yield from iter_call_exprs(st.value)
        elif isinstance(st, ir.IfBranch):
            yield from iter_call_exprs(st.test)
            yield from iter_calls(st.body)
            yield from iter_calls(st.orelse)
        elif isinstance(st, ir.ForLoop):
            yield from iter_call_exprs(st.iter)
            yield from iter_calls(st.body)
        elif isinstance(st, ir.WhileLoop):
            yield from iter_calls(st.body)
        elif isinstance(st, ir.TryBlock):
            yield from iter_calls(st.body)
            for h in st.handlers:
                yield from iter_calls(h)
            yield from iter_calls(st.finalbody)
        elif isinstance(st, ir.WithBlock):
            for _name, e in st.items:
                yield from iter_call_exprs(e)
            yield from iter_calls(st.body)


def module_calls(mod: ir.Module) -> Iterator[ir.Call]:
    """Every Call in a module - inside functions and at module top level."""
    for fn in mod.functions:
        yield from iter_calls(fn.body)
    if mod.toplevel is not None:
        yield from iter_calls(mod.toplevel.body)
