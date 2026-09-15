"""Python frontend: lowers Python source into the normalized taint IR.

SAFETY: this module only ever calls `ast.parse` on source *text*. It never
imports, execs, evals, or otherwise runs any code from the scanned project.

Responsibilities:
- parse (a file that fails to parse is skipped with a warning, never a crash)
- resolve import aliases so IR paths are canonical (`sp.run` -> `subprocess.run`)
- lower expressions/statements into IR nodes the engine understands
- collect functions (including methods and nested functions) plus the
  module-level statements as a pseudo-function
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from palisade_sec import ir


@dataclass
class ParseFailure:
    path: str
    reason: str


class PythonFrontend:
    """Lowers one Python file at a time into an `ir.Module`."""

    name = "python"
    extensions = (".py", ".pyi")

    def lower_file(self, path: str, rel_path: str, source: str) -> ir.Module | ParseFailure:
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, ValueError, RecursionError) as exc:
            return ParseFailure(path=path, reason=str(exc))
        lines = source.splitlines()
        stem = rel_path[:-4] if rel_path.endswith(".pyi") else rel_path[:-3]
        stem = stem.replace("/", ".").replace("\\", ".")
        if stem.endswith(".__init__"):
            stem = stem[: -len(".__init__")]
        lowerer = _Lowerer(path=path, rel_path=rel_path, stem=stem, lines=lines)
        return lowerer.lower_module(tree)


class _Lowerer:
    def __init__(self, path: str, rel_path: str, stem: str, lines: list[str]):
        self.path = path
        self.rel_path = rel_path
        self.stem = stem
        self.lines = lines
        self.aliases: dict[str, str] = {}
        self.functions: list[ir.FuncDef] = []

    # -- helpers ----------------------------------------------------------

    def loc(self, node: ast.AST) -> ir.Loc:
        line = getattr(node, "lineno", 0)
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        return ir.Loc(
            file=self.rel_path, line=line, col=getattr(node, "col_offset", 0), snippet=snippet
        )

    def dotted_path(self, node: ast.AST) -> str:
        """Dotted path of a Name/Attribute chain, alias-resolved. "" if not one."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            root = self.aliases.get(cur.id, cur.id)
            parts.append(root)
            return ".".join(reversed(parts))
        return ""

    def root_var(self, node: ast.AST) -> str:
        cur = node
        while isinstance(cur, (ast.Attribute, ast.Subscript)):
            cur = cur.value
        return cur.id if isinstance(cur, ast.Name) else ""

    # -- module -----------------------------------------------------------

    def lower_module(self, tree: ast.Module) -> ir.Module:
        # First pass: record imports so alias resolution covers the whole file
        # (imports at the bottom are rare but legal).
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = (
                        a.name if a.asname else a.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    if a.name == "*":
                        continue
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
            elif isinstance(node, ast.ImportFrom) and node.level > 0:
                # relative import: resolve against this module's package
                pkg_parts = self.stem.split(".")[: -node.level] if self.stem else []
                base = ".".join(pkg_parts + ([node.module] if node.module else []))
                for a in node.names:
                    if a.name == "*":
                        continue
                    self.aliases[a.asname or a.name] = f"{base}.{a.name}" if base else a.name

        top_stmts: list[ir.Stmt] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.collect_function(node, class_name=None, prefix=self.stem)
            elif isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.collect_function(
                            item, class_name=node.name, prefix=f"{self.stem}.{node.name}"
                        )
            else:
                lowered = self.lower_stmt(node)
                if lowered:
                    top_stmts.extend(lowered)

        toplevel = ir.FuncDef(
            name="<module>",
            qualname=f"{self.stem}.<module>",
            params=[],
            body=top_stmts,
            loc=ir.Loc(file=self.rel_path, line=1),
        )
        return ir.Module(
            path=self.path,
            rel_path=self.rel_path,
            stem=self.stem,
            functions=self.functions,
            toplevel=toplevel,
            imports=dict(self.aliases),
        )

    def collect_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        class_name: str | None,
        prefix: str,
    ) -> None:
        params = [a.arg for a in node.args.posonlyargs + node.args.args]
        if node.args.vararg:
            params.append(node.args.vararg.arg)
        params += [a.arg for a in node.args.kwonlyargs]
        body: list[ir.Stmt] = []
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.collect_function(child, class_name=None, prefix=f"{prefix}.{node.name}")
            elif isinstance(child, ast.ClassDef):
                for item in child.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.collect_function(
                            item, class_name=child.name, prefix=f"{prefix}.{node.name}.{child.name}"
                        )
            else:
                body.extend(self.lower_stmt(child))
        self.functions.append(
            ir.FuncDef(
                name=node.name,
                qualname=f"{prefix}.{node.name}",
                params=params,
                body=body,
                loc=self.loc(node),
                class_name=class_name,
            )
        )

    # -- statements ---------------------------------------------------------

    def lower_stmt(self, node: ast.stmt) -> list[ir.Stmt]:
        loc = self.loc(node)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            return [self.lower_assign(node, loc)]
        if isinstance(node, ast.Expr):
            return [ir.ExprStmt(loc=loc, value=self.lower_expr(node.value))]
        if isinstance(node, ast.Return):
            return [ir.Return(loc=loc, value=self.lower_expr(node.value) if node.value else None)]
        if isinstance(node, ast.If):
            return [self.lower_if(node, loc)]
        if isinstance(node, (ast.For, ast.AsyncFor)):
            keys = self.target_keys(node.target)
            body = self.lower_block(node.body) + self.lower_block(node.orelse)
            return [
                ir.ForLoop(loc=loc, target_keys=keys, iter=self.lower_expr(node.iter), body=body)
            ]
        if isinstance(node, ast.While):
            return [ir.WhileLoop(loc=loc, body=self.lower_block(node.body + node.orelse))]
        if isinstance(node, ast.Try):
            return [
                ir.TryBlock(
                    loc=loc,
                    body=self.lower_block(node.body + node.orelse),
                    handlers=[self.lower_block(h.body) for h in node.handlers],
                    finalbody=self.lower_block(node.finalbody),
                )
            ]
        if isinstance(node, (ast.With, ast.AsyncWith)):
            items: list[tuple[str | None, ir.Expr]] = []
            for item in node.items:
                var = None
                if item.optional_vars is not None:
                    keys = self.target_keys(item.optional_vars)
                    var = keys[0] if keys else None
                items.append((var, self.lower_expr(item.context_expr)))
            return [ir.WithBlock(loc=loc, items=items, body=self.lower_block(node.body))]
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global, ast.Nonlocal)):
            return []
        if isinstance(node, ast.Raise):
            return [ir.Return(loc=loc, value=None)]  # terminates like a return
        if isinstance(node, (ast.Assert, ast.Delete, ast.Break, ast.Continue)):
            return []
        # Anything else: keep expressions visible so calls inside still count.
        exprs = [
            self.lower_expr(child)
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
        ]
        if exprs:
            return [ir.ExprStmt(loc=loc, value=ir.Unknown(loc=loc, children=exprs))]
        return []

    def lower_block(self, stmts: list[ast.stmt]) -> list[ir.Stmt]:
        out: list[ir.Stmt] = []
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # nested defs collected elsewhere / skipped in blocks
            out.extend(self.lower_stmt(s))
        return out

    def target_keys(self, target: ast.expr) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name) and target.value.id == "self":
                return [f"self.{target.attr}"]
            root = self.root_var(target)
            return [root] if root else []
        if isinstance(target, ast.Subscript):
            root = self.root_var(target)
            return [f"+{root}"] if root else []  # "+x": augment, don't replace
        if isinstance(target, (ast.Tuple, ast.List)):
            keys: list[str] = []
            for elt in target.elts:
                if isinstance(elt, ast.Starred):
                    elt = elt.value
                keys.extend(self.target_keys(elt))
            return keys
        return []

    def lower_assign(
        self, node: ast.Assign | ast.AnnAssign | ast.AugAssign, loc: ir.Loc
    ) -> ir.Stmt:
        if isinstance(node, ast.Assign):
            keys: list[str] = []
            for t in node.targets:
                keys.extend(self.target_keys(t))
            value = self.lower_expr(node.value)
        elif isinstance(node, ast.AnnAssign):
            keys = self.target_keys(node.target)
            value = self.lower_expr(node.value) if node.value else ir.Const(loc=loc)
        else:  # AugAssign: x += y keeps x's old taint
            keys = self.target_keys(node.target)
            keys = [f"+{k}" if not k.startswith("+") else k for k in keys]
            value = self.lower_expr(node.value)
        return ir.Assign(loc=loc, targets=keys, value=value)

    def lower_if(self, node: ast.If, loc: ir.Loc) -> ir.IfBranch:
        test_names: list[str] = []
        test_calls: list[str] = []
        negated = False
        test = node.test
        while isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            negated = not negated
            test = test.operand
        literal_membership = False
        guard_var = ""
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], (ast.In, ast.NotIn))
        ):
            if isinstance(test.ops[0], ast.NotIn):
                negated = not negated
            guard_var = self.root_var(test.left)
            comparator = test.comparators[0]
            if isinstance(comparator, (ast.Tuple, ast.List, ast.Set)) and all(
                isinstance(e, ast.Constant) for e in comparator.elts
            ):
                literal_membership = True
        elif isinstance(test, ast.Compare) and any(isinstance(op, ast.NotIn) for op in test.ops):
            negated = not negated
        for sub in ast.walk(node.test):
            if isinstance(sub, (ast.Name, ast.Attribute)):
                p = self.dotted_path(sub)
                if p:
                    test_names.append(p)
            elif isinstance(sub, ast.Call):
                p = self.dotted_path(sub.func)
                if p:
                    test_calls.append(p)
        body = self.lower_block(node.body)
        terminates = bool(node.body) and isinstance(
            node.body[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break)
        )
        return ir.IfBranch(
            loc=loc,
            test=self.lower_expr(node.test),
            test_names=test_names,
            test_calls=test_calls,
            body=body,
            orelse=self.lower_block(node.orelse),
            terminates=terminates,
            negated=negated,
            literal_membership=literal_membership,
            guard_var=guard_var,
        )

    # -- expressions --------------------------------------------------------

    def lower_expr(self, node: ast.expr) -> ir.Expr:
        loc = self.loc(node)
        if isinstance(node, ast.Constant):
            return ir.Const(loc=loc, value=node.value)
        if isinstance(node, ast.Name):
            root = self.aliases.get(node.id, node.id)
            return ir.VarRef(loc=loc, path=root, base_var=node.id)
        if isinstance(node, ast.Attribute):
            path = self.dotted_path(node)
            if path:
                return ir.VarRef(loc=loc, path=path, base_var=self.root_var(node))
            return ir.Member(loc=loc, base=self.lower_expr(node.value), path="")
        if isinstance(node, ast.Subscript):
            base = self.lower_expr(node.value)
            return ir.Member(loc=loc, base=base, path=self.dotted_path(node.value))
        if isinstance(node, ast.Await):
            return self.lower_expr(node.value)
        if isinstance(node, ast.Starred):
            return self.lower_expr(node.value)
        if isinstance(node, ast.Call):
            return self.lower_call(node, loc)
        if isinstance(node, ast.JoinedStr):
            parts = [
                self.lower_expr(v.value if isinstance(v, ast.FormattedValue) else v)
                for v in node.values
                if not isinstance(v, ast.Constant)
            ]
            return ir.StrJoin(loc=loc, parts=parts)
        if isinstance(node, ast.BinOp):
            return ir.StrJoin(
                loc=loc, parts=[self.lower_expr(node.left), self.lower_expr(node.right)]
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return ir.Collection(loc=loc, items=[self.lower_expr(e) for e in node.elts])
        if isinstance(node, ast.Dict):
            items = [self.lower_expr(k) for k in node.keys if k is not None]
            items += [self.lower_expr(v) for v in node.values]
            return ir.Collection(loc=loc, items=items)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self.lower_comprehension(node.elt, node.generators, loc)
        if isinstance(node, ast.DictComp):
            joined = ir.StrJoin(
                loc=loc, parts=[self.lower_expr(node.key), self.lower_expr(node.value)]
            )
            return self.lower_comprehension_expr(joined, node.generators, loc)
        if isinstance(node, ast.IfExp):
            return ir.Unknown(
                loc=loc, children=[self.lower_expr(node.body), self.lower_expr(node.orelse)]
            )
        if isinstance(node, ast.BoolOp):
            return ir.Unknown(loc=loc, children=[self.lower_expr(v) for v in node.values])
        if isinstance(node, ast.Compare):
            return ir.Const(loc=loc, value=True)  # comparisons yield clean bools
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return ir.Const(loc=loc, value=True)
            return self.lower_expr(node.operand)
        if isinstance(node, ast.Lambda):
            return ir.Const(loc=loc, value=None)
        if isinstance(node, ast.NamedExpr):
            return self.lower_expr(node.value)
        children = [
            self.lower_expr(c) for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)
        ]
        return ir.Unknown(loc=loc, children=children)

    def lower_comprehension(
        self, elt: ast.expr, generators: list[ast.comprehension], loc: ir.Loc
    ) -> ir.Expr:
        return self.lower_comprehension_expr(self.lower_expr(elt), generators, loc)

    def lower_comprehension_expr(
        self, element: ir.Expr, generators: list[ast.comprehension], loc: ir.Loc
    ) -> ir.Expr:
        # Comprehension taint = element taint ∪ iterable taint. The iteration
        # variable is bound to the iterable, so folding the iterable in covers
        # `[f(x) for x in tainted]` without per-binding tracking.
        parts: list[ir.Expr] = [element]
        for gen in generators:
            parts.append(self.lower_expr(gen.iter))
        return ir.Collection(loc=loc, items=parts)

    def lower_call(self, node: ast.Call, loc: ir.Loc) -> ir.Expr:
        func_path = self.dotted_path(node.func)
        receiver: ir.Expr | None = None
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            base = node.func.value
            # String-building methods become StrJoin so taint flows naturally.
            if method == "format":
                parts = [self.lower_expr(base)]
                parts += [self.lower_expr(a) for a in node.args]
                parts += [self.lower_expr(k.value) for k in node.keywords]
                return ir.StrJoin(loc=loc, parts=parts)
            if method == "join" and len(node.args) == 1:
                return ir.StrJoin(
                    loc=loc, parts=[self.lower_expr(base), self.lower_expr(node.args[0])]
                )
            receiver = self.lower_expr(base)
            if not func_path:
                # method on a non-trivial base, e.g. resp.choices[0].message.strip()
                func_path = f"*.{method}"
        args = [self.lower_expr(a) for a in node.args if not isinstance(a, ast.Starred)]
        star_args = [self.lower_expr(a.value) for a in node.args if isinstance(a, ast.Starred)]
        kwargs: dict[str, ir.Expr] = {}
        for kw in node.keywords:
            if kw.arg is None:
                star_args.append(self.lower_expr(kw.value))
            else:
                kwargs[kw.arg] = self.lower_expr(kw.value)
        return ir.Call(
            loc=loc,
            func_path=func_path,
            receiver=receiver,
            args=args,
            kwargs=kwargs,
            star_args=star_args,
        )
