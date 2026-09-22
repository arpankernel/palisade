"""JavaScript/TypeScript frontend: lowers JS/TS source into the taint IR
via tree-sitter. This is the proof of the frontend/IR split: the engine and
the YAML rules are untouched - the same `chat.completions.create`, `eval`,
`child_process.exec` patterns match because the JS SDKs mirror the Python
ones and IR paths are language-neutral dotted paths.

SAFETY: parses source text only; never executes scanned code.

Optional: requires the `js` extra (`pip install "palisade-sec[js]"`). When
the packages are missing, the scanner skips JS/TS files with a note.

Conventions used during lowering:
- `this` is spelled `self` in IR paths, so class-field tracking
  (`this.code = ...` -> "self.code") and hierarchy resolution work as-is.
- Express-style inline handlers (`app.post('/x', (req, res) => {...})`) are
  collected as functions, so their bodies are analyzed as entry points and
  `req.body` matches the rule sources by name.
"""

from __future__ import annotations

from palisade_sec import ir
from palisade_sec.frontends.ast_python import ParseFailure

try:
    import tree_sitter_javascript as _tsjs
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser

    AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    AVAILABLE = False


_COMPARISON_OPS = {"==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof"}
_TERMINATORS = {"return_statement", "throw_statement", "break_statement", "continue_statement"}
_FUNC_NODES = {"arrow_function", "function_expression", "function", "generator_function"}


class JavaScriptFrontend:
    name = "javascript"
    extensions = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")

    def __init__(self) -> None:
        if not AVAILABLE:  # pragma: no cover
            raise ImportError("tree-sitter extras not installed (pip install palisade-sec[js])")
        self._parsers = {
            "js": Parser(Language(_tsjs.language())),
            "ts": Parser(Language(_tsts.language_typescript())),
            "tsx": Parser(Language(_tsts.language_tsx())),
        }

    def lower_file(self, path: str, rel_path: str, source: str) -> ir.Module | ParseFailure:
        low = rel_path.lower()
        if low.endswith(".tsx"):
            parser = self._parsers["tsx"]
        elif low.endswith(".ts"):
            parser = self._parsers["ts"]
        else:
            parser = self._parsers["js"]
        data = source.encode("utf-8", errors="replace")
        try:
            tree = parser.parse(data)
        except Exception as exc:  # pragma: no cover - tree-sitter rarely raises
            return ParseFailure(path=path, reason=str(exc))
        stem = rel_path
        for ext in self.extensions:
            if low.endswith(ext):
                stem = rel_path[: -len(ext)]
                break
        stem = stem.replace("/", ".").replace("\\", ".")
        lowerer = _JsLowerer(path, rel_path, stem, data, source.splitlines())
        try:
            return lowerer.lower(tree.root_node)
        except RecursionError:
            return ParseFailure(path=path, reason="nesting too deep to analyze")


class _JsLowerer:
    def __init__(self, path: str, rel_path: str, stem: str, data: bytes, lines: list[str]):
        self.path = path
        self.rel_path = rel_path
        self.stem = stem
        self.data = data
        self.lines = lines
        self.aliases: dict[str, str] = {}
        self.functions: list[ir.FuncDef] = []
        self.class_bases: dict[str, list[str]] = {}
        self._anon = 0

    # -- helpers ------------------------------------------------------------

    def text(self, node) -> str:
        return self.data[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def loc(self, node) -> ir.Loc:
        row = node.start_point[0]
        snippet = self.lines[row].strip() if row < len(self.lines) else ""
        if len(snippet) > 200:  # redaction: never carry whole pathological lines
            snippet = snippet[:200] + "…"
        return ir.Loc(file=self.rel_path, line=row + 1, col=node.start_point[1], snippet=snippet)

    def _unwrap(self, node):
        while node is not None and node.type in ("parenthesized_expression", "await_expression"):
            inner = node.child_by_field_name("expression") or next(
                (c for c in node.named_children), None
            )
            if inner is None:
                break
            node = inner
        return node

    def dotted(self, node) -> str:
        """Dotted path of an identifier / member chain; '' if not a chain."""
        node = self._unwrap(node)
        parts: list[str] = []
        while node is not None and node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is None:
                return ""
            parts.append(self.text(prop))
            node = self._unwrap(node.child_by_field_name("object"))
        if node is None:
            return ""
        if node.type == "identifier":
            root = self.aliases.get(self.text(node), self.text(node))
            parts.append(root)
        elif node.type == "this":
            parts.append("self")
        else:
            return ""
        return ".".join(reversed(parts))

    def root_var(self, node) -> str:
        node = self._unwrap(node)
        while node is not None and node.type in ("member_expression", "subscript_expression"):
            node = self._unwrap(node.child_by_field_name("object"))
        if node is None:
            return ""
        if node.type == "identifier":
            return self.text(node)
        if node.type == "this":
            return "self"
        return ""

    @staticmethod
    def _module_name(raw: str) -> str:
        name = raw.strip("'\"`")
        if name.startswith("node:"):
            name = name[5:]
        return name.replace("/", ".")

    # -- entry ----------------------------------------------------------------

    def lower(self, root) -> ir.Module:
        self._collect_aliases(root)
        top: list[ir.Stmt] = []
        for child in root.named_children:
            top.extend(self.lower_stmt(child))
        toplevel = ir.FuncDef(
            name="<module>",
            qualname=f"{self.stem}.<module>",
            params=[],
            body=top,
            loc=ir.Loc(file=self.rel_path, line=1),
        )
        return ir.Module(
            path=self.path,
            rel_path=self.rel_path,
            stem=self.stem,
            functions=self.functions,
            toplevel=toplevel,
            imports=dict(self.aliases),
            class_bases=dict(self.class_bases),
        )

    def _collect_aliases(self, root) -> None:
        cursor = [root]
        while cursor:
            node = cursor.pop()
            if node.type == "import_statement":
                src = node.child_by_field_name("source")
                if src is None:
                    continue
                mod = self._module_name(self.text(src))
                for clause in node.named_children:
                    if clause.type != "import_clause":
                        continue
                    for item in clause.named_children:
                        if item.type == "identifier":  # default import
                            self.aliases[self.text(item)] = f"{mod}.{self.text(item)}"
                        elif item.type == "namespace_import":
                            ident = next(
                                (c for c in item.named_children if c.type == "identifier"), None
                            )
                            if ident is not None:
                                self.aliases[self.text(ident)] = mod
                        elif item.type == "named_imports":
                            for spec in item.named_children:
                                if spec.type != "import_specifier":
                                    continue
                                name = spec.child_by_field_name("name")
                                alias = spec.child_by_field_name("alias") or name
                                if name is not None and alias is not None:
                                    self.aliases[self.text(alias)] = f"{mod}.{self.text(name)}"
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                name = node.child_by_field_name("name")
                if value is not None and value.type == "call_expression":
                    fn = value.child_by_field_name("function")
                    if fn is not None and self.text(fn) == "require":
                        args = value.child_by_field_name("arguments")
                        arg = next((a for a in args.named_children), None) if args else None
                        if arg is not None and name is not None:
                            mod = self._module_name(self.text(arg))
                            if name.type == "identifier":
                                self.aliases[self.text(name)] = mod
                            elif name.type == "object_pattern":
                                for p in name.named_children:
                                    if p.type in (
                                        "shorthand_property_identifier_pattern",
                                        "shorthand_property_identifier",
                                    ):
                                        self.aliases[self.text(p)] = f"{mod}.{self.text(p)}"
            cursor.extend(node.named_children)

    # -- functions ------------------------------------------------------------

    def _params(self, params_node) -> list[str]:
        out: list[str] = []
        if params_node is None:
            return out
        stack = list(params_node.named_children)
        while stack:
            p = stack.pop(0)
            if p.type == "identifier":
                out.append(self.text(p))
            elif p.type in ("required_parameter", "optional_parameter"):
                pat = p.child_by_field_name("pattern")
                if pat is not None:
                    stack.insert(0, pat)
            elif p.type in ("assignment_pattern",):
                left = p.child_by_field_name("left")
                if left is not None:
                    stack.insert(0, left)
            elif p.type in ("object_pattern", "array_pattern", "rest_pattern"):
                for c in p.named_children:
                    stack.append(c)
            elif p.type in (
                "shorthand_property_identifier_pattern",
                "shorthand_property_identifier",
            ):
                out.append(self.text(p))
        return out

    def _has_allowlist_membership(self, node, params: list[str]) -> bool:
        """`ALLOWED.includes(code)` / `.has()` / `.indexOf()` where the input is
        the element looked up in a collection - an allowlist. A denylist search
        of the input (`code.includes("os.")`) or a substring test against a
        string literal (`"abc".includes(code)`) does not count."""
        literal = ("string", "template_string", "number")
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                if fn is not None and fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    recv = fn.child_by_field_name("object")
                    args = n.child_by_field_name("arguments")
                    first = args.named_children[0] if args and args.named_children else None
                    if (
                        prop is not None
                        and self.text(prop) in ("includes", "has", "indexOf")
                        and recv is not None
                        and recv.type not in literal
                        and not (recv.type == "identifier" and self.text(recv) in params)
                        and first is not None
                        and first.type not in literal
                    ):
                        return True
            stack.extend(n.named_children)
        return False

    def collect_function(self, node, name: str, class_name: str | None) -> None:
        body = node.child_by_field_name("body")
        stmts: list[ir.Stmt] = []
        if body is not None:
            if body.type == "statement_block":
                for c in body.named_children:
                    stmts.extend(self.lower_stmt(c))
            else:  # expression-bodied arrow: implicit return
                stmts.append(ir.Return(loc=self.loc(body), value=self.lower_expr(body)))
        params = self._params(node.child_by_field_name("parameters"))
        if class_name:
            params = ["self", *params]
        decorators: list[str] = []
        prev = node.prev_named_sibling
        while prev is not None and prev.type == "decorator":
            inner = next((c for c in prev.named_children), None)
            if inner is not None:
                if inner.type == "call_expression":
                    inner = inner.child_by_field_name("function")
                d = self.dotted(inner) if inner is not None else ""
                if d:
                    decorators.append(d)
            prev = prev.prev_named_sibling
        self.functions.append(
            ir.FuncDef(
                name=name,
                qualname=f"{self.stem}.{class_name + '.' if class_name else ''}{name}",
                params=params,
                body=stmts,
                loc=self.loc(node),
                class_name=class_name,
                has_allowlist_membership=self._has_allowlist_membership(node, params),
                decorators=decorators,
            )
        )

    def _maybe_collect_inline(self, node, hint: str | None = None) -> bool:
        node = self._unwrap(node) if node is not None else None
        if node is not None and node.type in _FUNC_NODES:
            if hint is None:
                self._anon += 1
                hint = f"<handler:{self._anon}>"
            self.collect_function(node, hint, class_name=None)
            return True
        return False

    def collect_class(self, node) -> None:
        name_node = node.child_by_field_name("name")
        cls = self.text(name_node) if name_node is not None else "<anon-class>"
        bases: list[str] = []
        for c in node.named_children:
            if c.type == "class_heritage":
                for b in c.named_children:
                    d = self.dotted(b)
                    if d:
                        bases.append(d)
        self.class_bases[cls] = bases
        body = node.child_by_field_name("body")
        if body is None:
            return
        for member in body.named_children:
            if member.type == "method_definition":
                mname = member.child_by_field_name("name")
                self.collect_function(
                    member, self.text(mname) if mname is not None else "<method>", cls
                )

    # -- statements -------------------------------------------------------------

    def lower_stmt(self, node) -> list[ir.Stmt]:
        t = node.type
        loc = self.loc(node)
        if t in ("lexical_declaration", "variable_declaration"):
            out: list[ir.Stmt] = []
            for decl in node.named_children:
                if decl.type != "variable_declarator":
                    continue
                name = decl.child_by_field_name("name")
                value = decl.child_by_field_name("value")
                if value is not None and self._unwrap(value).type in _FUNC_NODES:
                    if name is not None and name.type == "identifier":
                        self.collect_function(self._unwrap(value), self.text(name), None)
                    else:
                        self._maybe_collect_inline(value)
                    continue
                if value is not None and value.type == "class":
                    self.collect_class(value)
                    continue
                targets = self._pattern_targets(name)
                out.append(
                    ir.Assign(
                        loc=loc,
                        targets=targets,
                        value=self.lower_expr(value) if value is not None else ir.Const(loc=loc),
                    )
                )
            return out
        if t == "expression_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr is None:
                return []
            if expr.type == "assignment_expression":
                left = expr.child_by_field_name("left")
                right = expr.child_by_field_name("right")
                if right is not None and self._unwrap(right).type in _FUNC_NODES:
                    hint = self.dotted(left) if left is not None else ""
                    self._maybe_collect_inline(right, hint.split(".")[-1] if hint else None)
                    return []
                return [
                    ir.Assign(
                        loc=loc,
                        targets=self._pattern_targets(left),
                        value=self.lower_expr(right) if right is not None else None,
                    )
                ]
            if expr.type == "augmented_assignment_expression":
                left = expr.child_by_field_name("left")
                right = expr.child_by_field_name("right")
                targets = [f"+{k}" for k in self._pattern_targets(left)]
                return [
                    ir.Assign(
                        loc=loc,
                        targets=targets,
                        value=self.lower_expr(right) if right is not None else None,
                    )
                ]
            return [ir.ExprStmt(loc=loc, value=self.lower_expr(expr))]
        if t == "return_statement":
            value = next((c for c in node.named_children), None)
            return [ir.Return(loc=loc, value=self.lower_expr(value) if value is not None else None)]
        if t == "throw_statement":
            return [ir.Return(loc=loc, value=None, raises=True)]
        if t == "if_statement":
            return [self.lower_if(node, loc)]
        if t in ("for_statement", "for_in_statement"):
            body = node.child_by_field_name("body")
            stmts = self.lower_block(body)
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            return [
                ir.ForLoop(
                    loc=loc,
                    target_keys=self._pattern_targets(left) if left is not None else [],
                    iter=self.lower_expr(right) if right is not None else None,
                    body=stmts,
                )
            ]
        if t in ("while_statement", "do_statement"):
            return [ir.WhileLoop(loc=loc, body=self.lower_block(node.child_by_field_name("body")))]
        if t == "try_statement":
            handlers = []
            handler = node.child_by_field_name("handler")
            if handler is not None:
                handlers.append(self.lower_block(handler.child_by_field_name("body")))
            final = node.child_by_field_name("finalizer")
            return [
                ir.TryBlock(
                    loc=loc,
                    body=self.lower_block(node.child_by_field_name("body")),
                    handlers=handlers,
                    finalbody=self.lower_block(final.child_by_field_name("body"))
                    if final is not None
                    else [],
                )
            ]
        if t == "function_declaration":
            name = node.child_by_field_name("name")
            self.collect_function(node, self.text(name) if name is not None else "<fn>", None)
            return []
        if t in ("class_declaration",):
            self.collect_class(node)
            return []
        if t == "export_statement":
            out = []
            for c in node.named_children:
                out.extend(self.lower_stmt(c))
            return out
        if t == "statement_block":
            out = []
            for c in node.named_children:
                out.extend(self.lower_stmt(c))
            return out
        if t in ("import_statement", "comment", "empty_statement"):
            return []
        if t in (
            "interface_declaration",
            "type_alias_declaration",
            "enum_declaration",
            "ambient_declaration",
        ):
            return []
        # fallback: surface any expressions so calls still count
        exprs = [self.lower_expr(c) for c in node.named_children]
        if exprs:
            return [ir.ExprStmt(loc=loc, value=ir.Unknown(loc=loc, children=exprs))]
        return []

    def lower_block(self, node) -> list[ir.Stmt]:
        if node is None:
            return []
        if node.type == "statement_block":
            out: list[ir.Stmt] = []
            for c in node.named_children:
                out.extend(self.lower_stmt(c))
            return out
        return self.lower_stmt(node)

    def _pattern_targets(self, node) -> list[str]:
        if node is None:
            return []
        node = self._unwrap(node)
        if node.type == "identifier":
            return [self.text(node)]
        if node.type == "member_expression":
            d = self.dotted(node)
            if d.startswith("self.") and d.count(".") == 1:
                return [d]
            root = self.root_var(node)
            return [f"+{root}"] if root else []
        if node.type == "subscript_expression":
            root = self.root_var(node)
            return [f"+{root}"] if root else []
        out: list[str] = []
        for c in node.named_children:
            out.extend(self._pattern_targets(c))
        return out

    def lower_if(self, node, loc: ir.Loc) -> ir.IfBranch:
        cond = node.child_by_field_name("condition")
        test = self._unwrap(cond)
        negated = False
        while (
            test is not None and test.type == "unary_expression" and self.text(test).startswith("!")
        ):
            negated = not negated
            test = self._unwrap(test.child_by_field_name("argument"))

        literal_membership = False
        guard_var = ""
        membership_name = ""
        if test is not None and test.type == "call_expression":
            fn = test.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                if prop is not None and self.text(prop) in ("includes", "has"):
                    args = test.child_by_field_name("arguments")
                    arg = next((a for a in args.named_children), None) if args else None
                    guard_var = self.root_var(arg) if arg is not None else ""
                    obj = self._unwrap(fn.child_by_field_name("object"))
                    if (
                        obj is not None
                        and obj.type == "array"
                        and all(c.type in ("string", "number") for c in obj.named_children)
                    ):
                        literal_membership = True
                    elif obj is not None:
                        membership_name = self.dotted(obj)

        test_names: list[str] = []
        test_calls: list[str] = []
        if cond is not None:
            stack = [cond]
            while stack:
                n = stack.pop()
                if n.type in ("identifier", "member_expression"):
                    d = self.dotted(n)
                    if d:
                        test_names.append(d)
                if n.type == "call_expression":
                    fn = n.child_by_field_name("function")
                    d = self.dotted(fn) if fn is not None else ""
                    if d:
                        test_calls.append(d)
                stack.extend(n.named_children)

        consequence = node.child_by_field_name("consequence")
        body = self.lower_block(consequence)
        terminates = False
        if consequence is not None:
            last = None
            if consequence.type == "statement_block":
                kids = consequence.named_children
                last = kids[-1] if kids else None
            else:
                last = consequence
            terminates = last is not None and last.type in _TERMINATORS
        alternative = node.child_by_field_name("alternative")
        orelse: list[ir.Stmt] = []
        if alternative is not None:
            for c in alternative.named_children:
                orelse.extend(self.lower_stmt(c))
        return ir.IfBranch(
            loc=loc,
            test=self.lower_expr(cond) if cond is not None else None,
            test_names=test_names,
            test_calls=test_calls,
            body=body,
            orelse=orelse,
            terminates=terminates,
            negated=negated,
            literal_membership=literal_membership,
            guard_var=guard_var,
            membership_name=membership_name,
        )

    # -- expressions --------------------------------------------------------------

    def lower_expr(self, node) -> ir.Expr:
        if node is None:
            return ir.Const(loc=ir.Loc(file=self.rel_path, line=0))
        node = self._unwrap(node)
        t = node.type
        loc = self.loc(node)
        if t in ("string", "number", "true", "false", "null", "undefined", "regex"):
            return ir.Const(loc=loc, value=self.text(node))
        if t == "identifier":
            name = self.text(node)
            return ir.VarRef(loc=loc, path=self.aliases.get(name, name), base_var=name)
        if t == "this":
            return ir.VarRef(loc=loc, path="self", base_var="self")
        if t == "member_expression":
            d = self.dotted(node)
            if d:
                return ir.VarRef(loc=loc, path=d, base_var=self.root_var(node))
            obj = node.child_by_field_name("object")
            return ir.Member(loc=loc, base=self.lower_expr(obj), path="")
        if t == "subscript_expression":
            obj = node.child_by_field_name("object")
            return ir.Member(loc=loc, base=self.lower_expr(obj), path=self.dotted(obj))
        if t == "template_string":
            parts = [
                self.lower_expr(next((c for c in sub.named_children), None))
                for sub in node.named_children
                if sub.type == "template_substitution"
            ]
            return ir.StrJoin(loc=loc, parts=parts)
        if t == "binary_expression":
            op_node = node.child_by_field_name("operator")
            op = self.text(op_node) if op_node is not None else "+"
            if op in _COMPARISON_OPS or op == "in":
                return ir.Const(loc=loc, value=True)
            return ir.StrJoin(
                loc=loc,
                parts=[
                    self.lower_expr(node.child_by_field_name("left")),
                    self.lower_expr(node.child_by_field_name("right")),
                ],
            )
        if t in ("call_expression", "new_expression"):
            return self.lower_call(node, loc)
        if t == "array":
            return ir.Collection(loc=loc, items=[self.lower_expr(c) for c in node.named_children])
        if t == "object":
            items: list[ir.Expr] = []
            for pair in node.named_children:
                if pair.type == "pair":
                    v = pair.child_by_field_name("value")
                    if v is not None:
                        items.append(self.lower_expr(v))
                elif pair.type == "shorthand_property_identifier":
                    name = self.text(pair)
                    items.append(ir.VarRef(loc=self.loc(pair), path=name, base_var=name))
                elif pair.type == "spread_element":
                    inner = next((c for c in pair.named_children), None)
                    if inner is not None:
                        items.append(self.lower_expr(inner))
            return ir.Collection(loc=loc, items=items)
        if t == "ternary_expression":
            return ir.Unknown(
                loc=loc,
                children=[
                    self.lower_expr(node.child_by_field_name("consequence")),
                    self.lower_expr(node.child_by_field_name("alternative")),
                ],
            )
        if t in _FUNC_NODES:
            self._maybe_collect_inline(node)
            return ir.Const(loc=loc)
        if t == "assignment_expression":
            return self.lower_expr(node.child_by_field_name("right"))
        if t in ("unary_expression",):
            return self.lower_expr(node.child_by_field_name("argument"))
        if t in ("spread_element", "as_expression", "non_null_expression", "satisfies_expression"):
            inner = next((c for c in node.named_children), None)
            return self.lower_expr(inner)
        children = [self.lower_expr(c) for c in node.named_children]
        return ir.Unknown(loc=loc, children=children)

    def lower_call(self, node, loc: ir.Loc) -> ir.Expr:
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        func_path = self.dotted(fn) if fn is not None else ""
        receiver: ir.Expr | None = None
        args_node = node.child_by_field_name("arguments")
        raw_args = list(args_node.named_children) if args_node is not None else []

        if fn is not None and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            method = self.text(prop) if prop is not None else ""
            if method in ("join", "concat"):
                parts = [self.lower_expr(obj)] + [self.lower_expr(a) for a in raw_args]
                return ir.StrJoin(loc=loc, parts=parts)
            receiver = self.lower_expr(obj)
            if not func_path:
                func_path = f"*.{method}"

        args: list[ir.Expr] = []
        star_args: list[ir.Expr] = []
        for a in raw_args:
            if a.type in _FUNC_NODES:
                self._maybe_collect_inline(a)
                args.append(ir.Const(loc=self.loc(a)))
            elif a.type == "spread_element":
                inner = next((c for c in a.named_children), None)
                if inner is not None:
                    star_args.append(self.lower_expr(inner))
            else:
                args.append(self.lower_expr(a))
        return ir.Call(
            loc=loc,
            func_path=func_path,
            receiver=receiver,
            args=args,
            kwargs={},
            star_args=star_args,
        )
