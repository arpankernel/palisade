"""The taint engine: abstract interpretation over the IR.

Per rule, every function is analyzed as an entry point with clean parameters
(sources arise inside: request.json, input(), sys.argv, ...). Calls to
project-local functions are followed inter-procedurally, bounded to
`max_hops` (default 3) function-boundary crossings.

Precision-over-recall decisions live here:
- A finding requires a COMPLETE source -> LLM -> sink path. Untrusted input
  reaching a sink without an LLM in between is out of scope (that's Bandit's
  job); LLM output from a constant developer prompt is not a finding.
- Sanitizers (allowlist, pydantic/marshmallow validation, int/enum casts,
  literal-membership guards) suppress taint entirely.
- Partial defenses (denylists, confirmation gates) do NOT suppress — the
  taint keeps flowing, flagged, and the finding is downgraded to MED "risky".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from palisade_sec import ir
from palisade_sec.engine.findings import Finding, TracePoint
from palisade_sec.engine.taint import (
    EMPTY,
    LLM,
    SOURCE,
    PartialHit,
    Taint,
    TaintSet,
    bump_hops,
    union,
    with_partial,
)
from palisade_sec.rules.schema import Rule, match_any_strict, match_lenient

# Builtin conversions that constrain the value enough to kill string taint.
_CAST_SANITIZERS = frozenset({"int", "float", "bool", "len", "abs", "hash", "ord", "round"})


@dataclass
class EngineResult:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Engine:
    def __init__(self, modules: list[ir.Module], rules: list[Rule], max_hops: int = 3):
        self.modules = modules
        self.rules = rules
        self.max_hops = max_hops
        # function resolution indexes (shared across rules)
        self.registry: dict[str, tuple[ir.FuncDef, ir.Module]] = {}
        self.by_name: dict[tuple[str, str], list[tuple[ir.FuncDef, ir.Module]]] = {}
        self.methods: dict[tuple[str, str, str], tuple[ir.FuncDef, ir.Module]] = {}
        for mod in modules:
            for fn in mod.functions:
                self.registry[fn.qualname] = (fn, mod)
                self.by_name.setdefault((mod.stem, fn.name), []).append((fn, mod))
                if fn.class_name:
                    self.methods[(mod.stem, fn.class_name, fn.name)] = (fn, mod)

    def run(self) -> EngineResult:
        result = EngineResult()
        seen: dict[tuple, Finding] = {}
        truncated: set[str] = set()
        for rule in self.rules:
            rr = _RuleRun(self, rule)
            rr.run()
            result.notes.extend(rr.notes)
            truncated |= rr.truncated
            for f in rr.findings:
                key = (
                    f.rule_id,
                    f.sink.file,
                    f.sink.line,
                    f.source.file,
                    f.source.line,
                    f.llm.file,
                    f.llm.line,
                )
                prev = seen.get(key)
                if prev is None:
                    seen[key] = f
                else:
                    # keep the least-degraded variant (no partials > partials)
                    if len(f.partial_defenses) < len(prev.partial_defenses):
                        seen[key] = f
        # collapse duplicates sharing a fingerprint (BL-4)
        by_fp: dict[str, Finding] = {}
        for f in seen.values():
            prev = by_fp.get(f.fingerprint)
            if prev is None:
                by_fp[f.fingerprint] = f
            else:
                prev.count += 1
        result.findings = sorted(by_fp.values(), key=lambda f: f.sort_key())
        if truncated:
            result.notes.append(
                f"inter-procedural analysis truncated at {self.max_hops} hops for "
                f"{len(truncated)} function(s); deeper call chains were not followed"
            )
        result.notes = sorted(set(result.notes))
        return result

    def resolve(
        self, path: str, module: ir.Module, class_name: str | None
    ) -> tuple[ir.FuncDef, ir.Module] | None:
        """Resolve a call path to a project-local function, if unambiguous."""
        if not path or path.startswith("*."):
            return None
        if path.startswith("self.") and class_name:
            hit = self.methods.get((module.stem, class_name, path[5:]))
            if hit:
                return hit
            return None
        if "." not in path:
            cands = self.by_name.get((module.stem, path), [])
            return cands[0] if len(cands) == 1 else None
        exact = self.registry.get(path)
        if exact:
            return exact
        suffix = "." + path
        cands2 = [v for q, v in self.registry.items() if q.endswith(suffix)]
        return cands2[0] if len(cands2) == 1 else None


class _RuleRun:
    def __init__(self, engine: Engine, rule: Rule):
        self.engine = engine
        self.rule = rule
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.truncated: set[str] = set()
        self.memo: dict[tuple, TaintSet] = {}
        self.in_progress: set[tuple] = set()
        # (module_stem, class_name) -> {"self.x": TaintSet}
        self.class_fields: dict[tuple[str, str], dict[str, TaintSet]] = {}

    def run(self) -> None:
        for mod in self.engine.modules:
            if mod.toplevel and mod.toplevel.body:
                _Exec(self, mod.toplevel, mod, {}, depth=0).run()
            plain = [f for f in mod.functions if not f.class_name]
            classes: dict[str, list[ir.FuncDef]] = {}
            for f in mod.functions:
                if f.class_name:
                    classes.setdefault(f.class_name, []).append(f)
            for f in plain:
                env = {p: EMPTY for p in f.params}
                _Exec(self, f, mod, env, depth=0).run()
            for cname, methods in classes.items():
                # pass 1 collects taints assigned to self.<field>; pass 2
                # re-analyzes with those fields pre-seeded (FN-5).
                for _pass in (1, 2):
                    fields = dict(self.class_fields.get((mod.stem, cname), {}))
                    for f in methods:
                        env: dict[str, TaintSet] = {p: EMPTY for p in f.params}
                        env.update(fields)
                        _Exec(self, f, mod, env, depth=0).run()

    def call_function(
        self,
        fn: ir.FuncDef,
        mod: ir.Module,
        pos_args: list[TaintSet],
        kw_args: dict[str, TaintSet],
        depth: int,
    ) -> TaintSet:
        if depth > self.engine.max_hops:
            self.truncated.add(fn.qualname)
            return union(*pos_args, *kw_args.values()) if (pos_args or kw_args) else EMPTY
        params = fn.params[1:] if fn.params and fn.params[0] in ("self", "cls") else fn.params
        env: dict[str, TaintSet] = {p: EMPTY for p in fn.params}
        for p, ts in zip(params, pos_args, strict=False):
            env[p] = bump_hops(ts)
        for name, ts in kw_args.items():
            if name in env:
                env[name] = bump_hops(ts)
        if fn.class_name:
            env.update(self.class_fields.get((mod.stem, fn.class_name), {}))
        sig = (fn.qualname, tuple(env.get(p, EMPTY) for p in fn.params))
        if sig in self.memo:
            return self.memo[sig]
        if sig in self.in_progress:
            return EMPTY  # recursion: cut the cycle
        self.in_progress.add(sig)
        try:
            ret = _Exec(self, fn, mod, env, depth=depth).run()
        finally:
            self.in_progress.discard(sig)
        self.memo[sig] = ret
        return ret

    def emit(self, taint: Taint, sink_loc: ir.Loc, sink_path: str) -> None:
        if taint.kind != LLM:
            return
        severity = "med" if taint.partials else self.rule.severity
        if taint.hops <= 1:
            confidence = "HIGH"
        elif taint.hops == 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        self.findings.append(
            Finding(
                rule_id=self.rule.id,
                title=self.rule.title,
                severity=severity,
                confidence=confidence,
                source=TracePoint(
                    file=taint.src_file,
                    line=taint.src_line,
                    snippet=taint.src_snippet,
                    detail=taint.src_pattern,
                ),
                llm=TracePoint(
                    file=taint.llm_file,
                    line=taint.llm_line,
                    snippet=taint.llm_snippet,
                    detail=taint.llm_pattern,
                ),
                sink=TracePoint(
                    file=sink_loc.file,
                    line=sink_loc.line,
                    snippet=sink_loc.snippet,
                    detail=sink_path,
                ),
                partial_defenses=list(taint.partials),
                attack=self.rule.attack,
                fix=self.rule.fix,
                references=list(self.rule.references),
            )
        )


class _Exec:
    """Executes one function body abstractly for one rule."""

    def __init__(
        self,
        rr: _RuleRun,
        fn: ir.FuncDef,
        mod: ir.Module,
        env: dict[str, TaintSet],
        depth: int,
    ):
        self.rr = rr
        self.rule = rr.rule
        self.fn = fn
        self.mod = mod
        self.env = env
        self.depth = depth
        self.ret: TaintSet = EMPTY

    def run(self) -> TaintSet:
        self.exec_block(self.fn.body)
        return self.ret

    # -- statements -------------------------------------------------------

    def exec_block(self, stmts: list[ir.Stmt]) -> None:
        for s in stmts:
            self.exec_stmt(s)

    def exec_stmt(self, s: ir.Stmt) -> None:
        if isinstance(s, ir.Assign):
            ts = self.eval(s.value) if s.value else EMPTY
            for key in s.targets:
                if key.startswith("+"):
                    k = key[1:]
                    self.env[k] = union(self.env.get(k, EMPTY), ts)
                    key = k
                else:
                    self.env[key] = ts
                if key.startswith("self.") and self.fn.class_name:
                    fields = self.rr.class_fields.setdefault(
                        (self.mod.stem, self.fn.class_name), {}
                    )
                    fields[key] = union(fields.get(key, EMPTY), self.env[key])
        elif isinstance(s, ir.ExprStmt):
            if s.value is not None:
                self.eval(s.value)
        elif isinstance(s, ir.Return):
            if s.value is not None:
                self.ret = union(self.ret, self.eval(s.value))
        elif isinstance(s, ir.IfBranch):
            self.exec_if(s)
        elif isinstance(s, ir.ForLoop):
            it = self.eval(s.iter) if s.iter else EMPTY
            for k in s.target_keys:
                self.env[k.lstrip("+")] = it
            self.exec_block(s.body)
        elif isinstance(s, ir.WhileLoop):
            self.exec_block(s.body)
        elif isinstance(s, ir.TryBlock):
            self.exec_block(s.body)
            for h in s.handlers:
                self.exec_block(h)
            self.exec_block(s.finalbody)
        elif isinstance(s, ir.WithBlock):
            for var, expr in s.items:
                ts = self.eval(expr)
                if var:
                    self.env[var] = ts
            self.exec_block(s.body)

    def exec_if(self, s: ir.IfBranch) -> None:
        if s.test is not None:
            self.eval(s.test)  # side effects (calls) inside the test still count

        guard_paths = list(s.test_names) + list(s.test_calls)
        san_hit = any(match_lenient(p, self.rule.sanitizers) for p in guard_paths)
        par_pat = next(
            (m for p in guard_paths if (m := match_lenient(p, self.rule.partial_defenses))),
            None,
        )
        # Enum/allowlist membership against a literal collection is a full
        # sanitizer (FP-3), unless the guard itself is a denylist by name.
        if s.literal_membership and not par_pat:
            san_hit = True

        guarded = [
            p.split(".")[0]
            for p in ([s.guard_var] if s.guard_var else []) + list(s.test_names)
            if p.split(".")[0] in self.env and self.env[p.split(".")[0]]
        ]
        guarded = list(dict.fromkeys(guarded))

        outer = self.env
        env_body = dict(outer)
        env_else = dict(outer)

        if san_hit and not par_pat:
            if s.negated:
                # `if x not in ALLOWED: <reject>` — the else/fall-through is safe
                for v in guarded:
                    env_else[v] = EMPTY
            else:
                # `if x in ALLOWED: <use>` — the body is safe
                for v in guarded:
                    env_body[v] = EMPTY

        if par_pat:
            hit = PartialHit(pattern=par_pat, file=s.loc.file, line=s.loc.line)
            # A denylist/confirmation gate was consulted: keep the taint but
            # mark everything it guards as only partially defended, on every
            # path from here on.
            for e in (env_body, env_else):
                for k, ts in list(e.items()):
                    if ts:
                        e[k] = with_partial(ts, hit)

        self.env = env_body
        self.exec_block(s.body)
        env_body = self.env
        self.env = env_else
        self.exec_block(s.orelse)
        env_else = self.env
        self.env = outer

        if s.terminates:
            merged = env_else
            if san_hit and not par_pat and s.negated:
                for v in guarded:
                    merged[v] = EMPTY
        else:
            keys = set(env_body) | set(env_else)
            merged = {k: union(env_body.get(k, EMPTY), env_else.get(k, EMPTY)) for k in keys}
        self.env.clear()
        self.env.update(merged)

    # -- expressions --------------------------------------------------------

    def eval(self, e: ir.Expr) -> TaintSet:
        if isinstance(e, ir.Const):
            return EMPTY
        if isinstance(e, ir.VarRef):
            return self.eval_varref(e)
        if isinstance(e, ir.Member):
            ts = self.eval(e.base) if e.base is not None else EMPTY
            if e.path:
                ts = union(ts, self.source_taint(e.path, e.loc))
            return ts
        if isinstance(e, ir.Call):
            return self.eval_call(e)
        if isinstance(e, (ir.StrJoin, ir.Collection)):
            parts = e.parts if isinstance(e, ir.StrJoin) else e.items
            return union(*(self.eval(p) for p in parts)) if parts else EMPTY
        if isinstance(e, ir.Unknown):
            return union(*(self.eval(c) for c in e.children)) if e.children else EMPTY
        return EMPTY

    def eval_varref(self, e: ir.VarRef) -> TaintSet:
        if e.path in self.env:
            return self.env[e.path]
        src = self.source_taint(e.path, e.loc)
        if src:
            return src
        if e.base_var and e.base_var in self.env:
            return self.env[e.base_var]
        if e.base_var:
            # attribute chain on a known local: resp.choices -> env["resp"]
            root = e.path.split(".")[0]
            if root in self.env:
                return self.env[root]
        return EMPTY

    def source_taint(self, path: str, loc: ir.Loc) -> TaintSet:
        spec = match_any_strict(path, self.rule.sources)
        if spec is None:
            return EMPTY
        pattern = next(p for p in spec.patterns if _matched(path, p))
        return frozenset(
            {
                Taint(
                    kind=SOURCE,
                    src_pattern=pattern,
                    src_file=loc.file,
                    src_line=loc.line,
                    src_snippet=loc.snippet,
                )
            }
        )

    def eval_call(self, c: ir.Call) -> TaintSet:
        arg_sets = [self.eval(a) for a in c.args]
        arg_sets += [self.eval(a) for a in c.star_args]
        kw_sets = {k: self.eval(v) for k, v in c.kwargs.items()}
        recv = self.eval(c.receiver) if c.receiver is not None else EMPTY
        all_args = union(*arg_sets, *kw_sets.values(), recv)
        path = c.func_path

        # 1) source calls: input(), request.get_json()
        src = self.source_taint(path, c.loc)
        if src:
            return src

        # 2) type-constraining builtins kill string taint (FP-3)
        if path in _CAST_SANITIZERS:
            return EMPTY

        # 3) sanitizers suppress (FP-1)
        if match_lenient(path, self.rule.sanitizers):
            return EMPTY

        # 4) partial defenses keep the taint, flagged (FN-11)
        par = match_lenient(path, self.rule.partial_defenses)
        if par:
            hit = PartialHit(pattern=par, file=c.loc.file, line=c.loc.line)
            return with_partial(all_args, hit)

        # 5) LLM call sites: source-tainted input => LLM-tainted output
        if match_any_strict(path, self.rule.llm_signatures):
            out: set[Taint] = set()
            for t in all_args:
                if t.kind == SOURCE:
                    out.add(
                        Taint(
                            kind=LLM,
                            src_pattern=t.src_pattern,
                            src_file=t.src_file,
                            src_line=t.src_line,
                            src_snippet=t.src_snippet,
                            llm_pattern=path,
                            llm_file=c.loc.file,
                            llm_line=c.loc.line,
                            llm_snippet=c.loc.snippet,
                            hops=t.hops,
                            partials=t.partials,
                        )
                    )
                elif t.kind == LLM:
                    out.add(t)  # chained LLM calls keep the original trace
            return frozenset(out)

        # 6) sinks
        sink_spec = match_any_strict(path, self.rule.sinks)
        if sink_spec is not None and _sink_armed(c, sink_spec):
            for t in all_args:
                self.rr.emit(t, c.loc, path)
            return EMPTY

        # 7) project-local functions: follow in, bounded (FN-1, FN-8)
        callee = self.engine_resolve(path)
        if callee is not None:
            fn, mod = callee
            return self.rr.call_function(fn, mod, arg_sets, kw_sets, self.depth + 1)

        # 8) unknown call: conservatively propagate argument taint
        #    (covers json.loads, .strip(), str(), custom helpers we can't see)
        return all_args

    def engine_resolve(self, path: str):
        return self.rr.engine.resolve(path, self.mod, self.fn.class_name)


def _matched(path: str, pattern: str) -> bool:
    from palisade_sec.rules.schema import match_strict

    return match_strict(path, pattern)


def _sink_armed(c: ir.Call, spec) -> bool:
    """Apply sink-shape guards: shell=True requirements and parameterized-SQL
    safety (FP-5)."""
    if spec.require_kwargs:
        for key, expected in spec.require_kwargs.items():
            actual = c.kwargs.get(key)
            if not isinstance(actual, ir.Const) or actual.value != expected:
                return False
    if spec.safe_if_extra_args:
        if len(c.args) >= 2:
            return False  # cursor.execute(query, params)
        if any(k in c.kwargs for k in ("params", "parameters", "args", "vars")):
            return False
    return True
