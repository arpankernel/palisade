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
- Partial defenses (denylists, confirmation gates) do NOT suppress - the
  taint keeps flowing, flagged, and the finding is downgraded to MED "risky".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from palisade_sec import ir
from palisade_sec.engine.findings import SEVERITY_ORDER, Finding, TracePoint
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
from palisade_sec.rules.schema import Rule, match_any_strict, match_lenient, match_lenient_spec

# Builtin conversions that constrain the value enough to kill string taint.
_CAST_SANITIZERS = frozenset({"int", "float", "bool", "len", "abs", "hash", "ord", "round"})


@dataclass
class EngineResult:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Distinct code locations where an untrusted source was minted, counted
    # once each no matter how many rules or evaluations touched them. Zero
    # means taint had nowhere to start, so "no findings" says nothing about
    # the code - it is an unchallenged scan, not a clean one. Scanning a
    # library without --assume-params-untrusted is the common way to get
    # here: library code has no `request.*`, no `input()`, no `sys.argv`, so
    # there is no source and a finding is impossible by construction.
    #
    # Deduplicated on purpose. Counting raw mint events multiplies by the
    # rule count (5 rules -> every source counted 5x), which reads as a
    # plausible number and is wrong by 5x - exactly the kind of figure that
    # ends up quoted in a README.
    sources_found: int = 0


class Engine:
    def __init__(
        self,
        modules: list[ir.Module],
        rules: list[Rule],
        max_hops: int = 3,
        assume_params_untrusted: bool = False,
    ):
        self.modules = modules
        self.rules = rules
        self.max_hops = max_hops
        # Library mode: parameters of public functions are untrusted sources.
        self.assume_params_untrusted = assume_params_untrusted
        self._verify_cache: dict[str, bool] = {}
        # function resolution indexes (shared across rules)
        self.registry: dict[str, tuple[ir.FuncDef, ir.Module]] = {}
        self.by_name: dict[tuple[str, str], list[tuple[ir.FuncDef, ir.Module]]] = {}
        # qualname last segment -> (qualname, value): lets resolve()'s dotted
        # suffix fallback scan only functions sharing the final name, instead of
        # the whole registry. Without this the fallback is O(call_sites x
        # total_functions) and large (esp. TS) repos scan quadratically.
        self.by_last: dict[str, list[tuple[str, tuple[ir.FuncDef, ir.Module]]]] = {}
        self.methods: dict[tuple[str, str, str], tuple[ir.FuncDef, ir.Module]] = {}
        # class-hierarchy indexes: (stem, class) -> base names; name -> classes
        self.class_bases: dict[tuple[str, str], list[str]] = {}
        self.classes_by_name: dict[str, list[tuple[str, str]]] = {}
        for mod in modules:
            for fn in mod.functions:
                self.registry[fn.qualname] = (fn, mod)
                self.by_name.setdefault((mod.stem, fn.name), []).append((fn, mod))
                self.by_last.setdefault(fn.qualname.rsplit(".", 1)[-1], []).append(
                    (fn.qualname, (fn, mod))
                )
                if fn.class_name:
                    self.methods[(mod.stem, fn.class_name, fn.name)] = (fn, mod)
            for cls, bases in mod.class_bases.items():
                self.class_bases[(mod.stem, cls)] = [b.split(".")[-1] for b in bases]
                self.classes_by_name.setdefault(cls, []).append((mod.stem, cls))

    def run(self) -> EngineResult:
        result = EngineResult()
        seen: dict[tuple, Finding] = {}
        truncated: set[str] = set()
        # Unioned across rules so a source every rule matches counts once.
        sources_seen: set[tuple[str, int, str]] = set()
        for rule in self.rules:
            rr = _RuleRun(self, rule)
            rr.run()
            result.notes.extend(rr.notes)
            truncated |= rr.truncated
            sources_seen |= rr.sources_seen
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
        # Dedup by SINK. One dangerous line is one thing to fix, even when
        # several rules match it or several untrusted sources reach it. A
        # library entry point commonly has both an `input()` path and a
        # public-parameter path converging on the same exec, and reporting
        # that twice is noise the developer cannot act on separately.
        # Keep the best-evidenced trace: most severe, then most direct
        # (fewest hops, i.e. highest confidence), then earliest rule.
        conf_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

        def better(a: Finding, b: Finding) -> bool:
            """Is `a` a better representative of this sink than `b`?"""
            return (
                SEVERITY_ORDER.get(a.severity, 9),
                conf_rank.get(a.confidence, 9),
                len(a.partial_defenses),
            ) < (
                SEVERITY_ORDER.get(b.severity, 9),
                conf_rank.get(b.confidence, 9),
                len(b.partial_defenses),
            )

        by_vuln: dict[tuple[str, int], Finding] = {}
        for f in by_fp.values():
            vuln_key = (f.sink.file, f.sink.line)
            prev_f = by_vuln.get(vuln_key)
            if prev_f is None:
                by_vuln[vuln_key] = f
            elif better(f, prev_f):
                f.count = max(f.count, prev_f.count + 1)
                by_vuln[vuln_key] = f
            else:
                prev_f.count += 1
        result.findings = sorted(by_vuln.values(), key=lambda f: f.sort_key())
        if truncated:
            result.notes.append(
                f"inter-procedural analysis truncated at {self.max_hops} hops for "
                f"{len(truncated)} function(s); deeper call chains were not followed"
            )
        result.notes = sorted(set(result.notes))
        result.sources_found = len(sources_seen)
        return result

    def resolve(
        self, path: str, module: ir.Module, class_name: str | None
    ) -> tuple[ir.FuncDef, ir.Module] | None:
        """Resolve a call path to a project-local function, if unambiguous."""
        if not path or path.startswith("*."):
            return None
        if path.startswith("self.") and class_name:
            return self.resolve_method(module.stem, class_name, path[5:])
        if "." not in path:
            cands = self.by_name.get((module.stem, path), [])
            return cands[0] if len(cands) == 1 else None
        exact = self.registry.get(path)
        if exact:
            return exact
        # Dotted-suffix fallback, scoped to functions whose last segment matches
        # (O(1) bucket lookup + a tiny filter) instead of the whole registry.
        suffix = "." + path
        bucket = self.by_last.get(path.rsplit(".", 1)[-1], [])
        cands2 = [v for q, v in bucket if q.endswith(suffix)]
        return cands2[0] if len(cands2) == 1 else None

    def resolve_method(
        self, stem: str, class_name: str, method: str
    ) -> tuple[ir.FuncDef, ir.Module] | None:
        """Resolve self.<method> through the class hierarchy.

        Order: the class itself, then ancestors (template methods defined in
        a base), then descendants - but only when exactly ONE descendant
        class implements the method (an abstract hook with a single provider
        is unambiguous; Vanna-style many-provider dispatch stays unresolved
        and is handled by stub propagation + custom wrapper rules).
        """
        # self + ancestors. A stub hit (abstract `raise NotImplementedError`)
        # is only provisional: the real implementation may live below.
        seen: set[tuple[str, str]] = set()
        stub_hit: tuple[ir.FuncDef, ir.Module] | None = None
        stack = [(stem, class_name)]
        while stack:
            key = stack.pop()
            if key in seen:
                continue
            seen.add(key)
            hit = self.methods.get((key[0], key[1], method))
            if hit:
                if not _is_stub(hit[0]):
                    return hit
                stub_hit = stub_hit or hit
            for base_name in self.class_bases.get(key, []):
                stack.extend(self.classes_by_name.get(base_name, []))
        # unique concrete descendant implementation
        ancestors = seen  # every class visited above is "this class or above"
        impls = [
            self.methods[(istem, icls, method)]
            for (istem, icls, m) in self.methods
            if m == method
            and not _is_stub(self.methods[(istem, icls, m)][0])
            and self._inherits_from(istem, icls, ancestors)
        ]
        if len(impls) == 1:
            return impls[0]
        return stub_hit

    def _inherits_from(self, stem: str, cls: str, ancestors: set[tuple[str, str]]) -> bool:
        seen: set[tuple[str, str]] = set()
        stack = [(stem, cls)]
        while stack:
            key = stack.pop()
            if key in seen:
                continue
            seen.add(key)
            if key in ancestors and key != (stem, cls):
                return True
            for base_name in self.class_bases.get(key, []):
                stack.extend(self.classes_by_name.get(base_name, []))
        return False

    def sanitizer_verified(self, path: str, module: ir.Module, class_name: str | None) -> bool:
        """Is a name-matched sanitizer believable?

        - Unresolvable (external library): True - we can't inspect it, and
          flagging every third-party sanitizer would violate precision.
          Known frameworks should use `trusted: true` in the rule instead.
        - Resolved project-local function: True only if its body shows a real
          allowlist/validation shape (a membership test, or a guard branch
          that raises/returns). Vanna's `_sanitize_plotly_code` - a cosmetic
          .replace() - fails this and gets downgraded, not suppressed.
        """
        target = self.resolve(path, module, class_name)
        if target is None:
            return True
        fn, fn_mod = target
        cached = self._verify_cache.get(fn.qualname)
        if cached is None:
            cached = _body_validates(fn)
            if not cached:
                # one level of delegation: validate() -> _impl() that validates
                for call_path in _iter_call_paths(fn.body):
                    inner = self.resolve(call_path, fn_mod, fn.class_name)
                    if inner is not None and _body_validates(inner[0]):
                        cached = True
                        break
            self._verify_cache[fn.qualname] = cached
        return cached


class _RuleRun:
    def __init__(self, engine: Engine, rule: Rule):
        self.engine = engine
        self.rule = rule
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.truncated: set[str] = set()
        # Distinct (file, line, pattern) sites where this rule minted an
        # untrusted source. A set, not a counter: the same site is reached
        # many times per pass and by every rule, and only the site count is
        # meaningful. See EngineResult.sources_found.
        self.sources_seen: set[tuple[str, int, str]] = set()
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
                _Exec(self, f, mod, self.entry_env(f), depth=0).run()
            for cname, methods in classes.items():
                # pass 1 collects taints assigned to self.<field>; pass 2
                # re-analyzes with those fields pre-seeded (FN-5).
                for _pass in (1, 2):
                    fields = dict(self.class_fields.get((mod.stem, cname), {}))
                    for f in methods:
                        env = self.entry_env(f)
                        env.update(fields)
                        _Exec(self, f, mod, env, depth=0).run()

    def entry_env(self, fn: ir.FuncDef) -> dict[str, TaintSet]:
        """Parameter taints for an entry-point analysis.

        Params are untrusted sources when (a) library mode
        (--assume-params-untrusted) and the function is public - libraries
        have no visible caller, so the caller IS the untrusted world
        (Vanna's `ask(question)`, CVE-2024-5565) - or (b) the function is a
        web-framework entry point per the rule's decorator-kind sources
        (FastAPI `@app.post` handlers receive the request as parameters)."""
        env: dict[str, TaintSet] = {p: EMPTY for p in fn.params}
        dec_specs = [sp for sp in self.rule.sources if sp.kind == "decorator"]
        is_route_handler = any(match_any_strict(d, dec_specs) is not None for d in fn.decorators)
        if is_route_handler or (
            self.engine.assume_params_untrusted and not fn.name.startswith("_")
        ):
            for p in fn.params:
                if p in ("self", "cls"):
                    continue
                self.sources_seen.add((fn.loc.file, fn.loc.line, f"param:{p}"))
                env[p] = frozenset(
                    {
                        Taint(
                            kind=SOURCE,
                            src_pattern=f"param:{p}",
                            src_file=fn.loc.file,
                            src_line=fn.loc.line,
                            src_snippet=fn.loc.snippet,
                        )
                    }
                )
        return env

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
            # A var's post-try taint is the JOIN over the branches that could
            # define it: the try-body running to completion, or a handler
            # firing after the body partially ran. Executing body then handlers
            # sequentially on one env let a handler's clean reassignment
            # (`except: code = "safe"`) erase taint the body established
            # (`try: code = <llm output>`), silently dropping the finding when
            # exec(code) runs the attacker-controlled path.
            before = dict(self.env)
            self.exec_block(s.body)
            branch_states = [dict(self.env)]
            for h in s.handlers:
                # A handler runs after an exception, so it may observe taint the
                # body established before raising: start from before | after-body.
                self.env = dict(before)
                for k, v in branch_states[0].items():
                    self.env[k] = union(self.env.get(k, EMPTY), v)
                self.exec_block(h)
                branch_states.append(dict(self.env))
            joined: dict[str, TaintSet] = {}
            for st in branch_states:
                for k, v in st.items():
                    joined[k] = union(joined.get(k, EMPTY), v)
            self.env = joined
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
        par_pat = next(
            (m for p in guard_paths if (m := match_lenient(p, self.rule.partial_defenses))),
            None,
        )
        # Sanitizer guards: a literal-enum membership (FP-3) or a trusted /
        # body-verified sanitizer name fully sanitizes; a sanitizer-named
        # project function whose body shows no validation shape only
        # downgrades (unverified sanitizer). A denylist name wins over both.
        san_hit = False
        unverified_san: str | None = None
        if not par_pat:
            if s.literal_membership:
                san_hit = True
            for p in guard_paths:
                spec_hit = match_lenient_spec(p, self.rule.sanitizers)
                if spec_hit is None:
                    continue
                if spec_hit[1].trusted or self.rr.engine.sanitizer_verified(
                    p, self.mod, self.fn.class_name
                ):
                    san_hit = True
                else:
                    unverified_san = p

        guarded = [
            p.split(".")[0]
            for p in ([s.guard_var] if s.guard_var else []) + list(s.test_names)
            if p.split(".")[0] in self.env and self.env[p.split(".")[0]]
        ]
        guarded = list(dict.fromkeys(guarded))

        outer = self.env
        env_body = dict(outer)
        env_else = dict(outer)

        if san_hit:
            if s.negated:
                # `if x not in ALLOWED: <reject>` - the else/fall-through is safe
                for v in guarded:
                    env_else[v] = EMPTY
            else:
                # `if x in ALLOWED: <use>` - the body is safe
                for v in guarded:
                    env_body[v] = EMPTY

        hit: PartialHit | None = None
        if par_pat:
            # A denylist/confirmation gate was consulted: keep the taint but
            # mark everything it guards as only partially defended, on every
            # path from here on.
            hit = PartialHit(pattern=par_pat, file=s.loc.file, line=s.loc.line)
        elif unverified_san and not san_hit:
            hit = PartialHit(
                pattern=unverified_san,
                file=s.loc.file,
                line=s.loc.line,
                kind="unverified_sanitizer",
            )
        if hit is not None:
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
            if san_hit and s.negated:
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
                ts = union(ts, self.source_taint_prefixed(e.path, e.loc))
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
        src = self.source_taint_prefixed(e.path, e.loc)
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

    def source_taint_prefixed(self, path: str, loc: ir.Loc) -> TaintSet:
        """Source match on the path or any dotted prefix: `req.body.q` is a
        source because `req.body` is (deep attribute reads of a source are
        still the source - Python hits this via subscripts, JS via chains)."""
        parts = path.split(".")
        for i in range(len(parts), 0, -1):
            ts = self.source_taint(".".join(parts[:i]), loc)
            if ts:
                return ts
        return EMPTY

    def source_taint(self, path: str, loc: ir.Loc) -> TaintSet:
        value_specs = [sp for sp in self.rule.sources if sp.kind != "decorator"]
        spec = match_any_strict(path, value_specs)
        if spec is None:
            return EMPTY
        pattern = next(p for p in spec.patterns if _matched(path, p))
        # Recorded on the rule run, not here: _Exec is per-function-body and
        # is discarded, while the record has to survive the whole pass.
        self.rr.sources_seen.add((loc.file, loc.line, pattern))
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
        pos_sets = [self.eval(a) for a in c.args]
        star_sets = [self.eval(a) for a in c.star_args]
        arg_sets = pos_sets + star_sets
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

        # 3) sanitizers (FP-1): trusted frameworks and body-verified project
        #    functions suppress; a sanitizer in name only (resolved body with
        #    no validation shape) downgrades to MED "unverified sanitizer" -
        #    Vanna's cosmetic _sanitize_plotly_code shipped CVE-2024-5565.
        san = match_lenient_spec(path, self.rule.sanitizers)
        if san is not None:
            if san[1].trusted or self.rr.engine.sanitizer_verified(
                path, self.mod, self.fn.class_name
            ):
                return EMPTY
            hit = PartialHit(
                pattern=path, file=c.loc.file, line=c.loc.line, kind="unverified_sanitizer"
            )
            return with_partial(all_args, hit)

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

        # 6) sinks. taint_args restricts which positional args are dangerous
        #    (exec's code argument, not its globals/locals dicts); star-args
        #    stay included since their position is unknown. A sink-named call
        #    that resolves to a real project function is followed instead -
        #    the true sink (or its absence) inside beats the name heuristic.
        sink_spec = match_any_strict(path, self.rule.sinks)
        if sink_spec is not None and _sink_armed(c, sink_spec):
            target = self.engine_resolve(path)
            if target is None or _is_stub(target[0]):
                if sink_spec.taint_args is None:
                    candidates = all_args
                else:
                    sel = [pos_sets[i] for i in sink_spec.taint_args if i < len(pos_sets)]
                    candidates = union(*sel, *star_sets)
                for t in candidates:
                    self.rr.emit(t, c.loc, path)
                return EMPTY

        # 7) mutating collection methods: x.append(tainted) taints x
        if c.receiver is not None and path.rsplit(".", 1)[-1] in _MUTATORS and all_args:
            recv_var = ""
            if isinstance(c.receiver, ir.VarRef):
                recv_var = c.receiver.base_var
            if recv_var and recv_var in self.env:
                self.env[recv_var] = union(self.env[recv_var], all_args)
            return EMPTY

        # 8) project-local functions: follow in, bounded (FN-1, FN-8).
        #    A stub body (abstract method: pass / ... / docstring /
        #    raise NotImplementedError) is a placeholder, not evidence the
        #    value is clean - propagate like an unknown call. Vanna's
        #    abstract system_message/user_message are the canonical case.
        callee = self.engine_resolve(path)
        if callee is not None:
            fn, mod = callee
            if _is_stub(fn):
                return all_args
            return self.rr.call_function(fn, mod, arg_sets, kw_sets, self.depth + 1)

        # 9) unknown call: conservatively propagate argument taint
        #    (covers json.loads, .strip(), str(), custom helpers we can't see)
        return all_args

    def engine_resolve(self, path: str):
        return self.rr.engine.resolve(path, self.mod, self.fn.class_name)


def _matched(path: str, pattern: str) -> bool:
    from palisade_sec.rules.schema import match_strict

    return match_strict(path, pattern)


_MUTATORS = frozenset({"append", "extend", "insert", "add", "appendleft", "update"})


def _is_stub(fn: ir.FuncDef) -> bool:
    """A body with no behavior: pass / ... / docstring-only / bare raise."""
    return all(
        (isinstance(s, ir.ExprStmt) and isinstance(s.value, ir.Const))
        or (isinstance(s, ir.Return) and s.value is None)
        for s in fn.body
    )


def _is_empty_params(expr: ir.Expr | None) -> bool:
    """An empty parameter binding: `execute(sql, ())` / `[]` / `{}` / None.

    An empty tuple/dict provides no placeholder substitution, so the SQL string
    itself is still what executes - parameterization is illusory and the sink
    stays armed. Empty `()`/`[]`/`{}` all lower to an empty Collection."""
    if isinstance(expr, ir.Collection):
        return not expr.items
    if isinstance(expr, ir.Const):
        return expr.value in (None, "", (), [], {})
    return False


def _sink_armed(c: ir.Call, spec) -> bool:
    """Apply sink-shape guards: shell=True requirements and parameterized-SQL
    safety (FP-5)."""
    if spec.require_kwargs:
        for key, expected in spec.require_kwargs.items():
            actual = c.kwargs.get(key)
            if not isinstance(actual, ir.Const) or actual.value != expected:
                return False
    if spec.safe_if_extra_args:
        # A real parameter binding disarms the sink; an empty one does not.
        if len(c.args) >= 2 and not _is_empty_params(c.args[1]):
            return False  # cursor.execute(query, params)
        for k in ("params", "parameters", "args", "vars"):
            v = c.kwargs.get(k)
            if k in c.kwargs and not _is_empty_params(v):
                return False
    return True


# Calls that constitute validation on their own (pattern matching / strict
# parsing of the whole value). Language-agnostic names welcome here.
# Strict validators only. `re.match` is deliberately excluded: it is a prefix
# match and, worse, a `re.match(...)` on any unrelated constant elsewhere in the
# body used to mark a cosmetic sanitizer "verified" (a silencing bypass).
_VALIDATOR_CALLS = frozenset({"re.fullmatch", "uuid.UUID", "ipaddress.ip_address"})


def _walk_stmts(stmts: list[ir.Stmt]):
    stack: list[ir.Stmt] = list(stmts)
    while stack:
        s = stack.pop()
        yield s
        if isinstance(s, ir.IfBranch):
            stack.extend(s.body)
            stack.extend(s.orelse)
        elif isinstance(s, (ir.ForLoop, ir.WhileLoop, ir.WithBlock)):
            stack.extend(s.body)
        elif isinstance(s, ir.TryBlock):
            stack.extend(s.body)
            for h in s.handlers:
                stack.extend(h)
            stack.extend(s.finalbody)


def _stmt_exprs(s: ir.Stmt):
    if isinstance(s, (ir.Assign, ir.ExprStmt, ir.Return)) and s.value is not None:
        yield s.value
    elif isinstance(s, ir.IfBranch) and s.test is not None:
        yield s.test
    elif isinstance(s, ir.ForLoop) and s.iter is not None:
        yield s.iter
    elif isinstance(s, ir.WithBlock):
        for _, e in s.items:
            yield e


def _iter_call_paths(stmts: list[ir.Stmt]):
    for s in _walk_stmts(stmts):
        for root in _stmt_exprs(s):
            stack: list[ir.Expr] = [root]
            while stack:
                e = stack.pop()
                if isinstance(e, ir.Call):
                    if e.func_path:
                        yield e.func_path
                    stack.extend(e.args)
                    stack.extend(e.star_args)
                    stack.extend(e.kwargs.values())
                    if e.receiver is not None:
                        stack.append(e.receiver)
                elif isinstance(e, ir.Member) and e.base is not None:
                    stack.append(e.base)
                elif isinstance(e, (ir.StrJoin, ir.Collection)):
                    stack.extend(e.parts if isinstance(e, ir.StrJoin) else e.items)
                elif isinstance(e, ir.Unknown):
                    stack.extend(e.children)


def _refs(expr: ir.Expr | None, names: set[str]) -> bool:
    """Does `expr` read any name in `names` (root variable of a dotted path)?"""
    if expr is None:
        return False
    if isinstance(expr, ir.VarRef):
        return expr.base_var in names
    if isinstance(expr, ir.Member):
        return _refs(expr.base, names)
    if isinstance(expr, ir.Call):
        return (
            _refs(expr.receiver, names)
            or any(_refs(a, names) for a in expr.args)
            or any(_refs(a, names) for a in expr.star_args)
            or any(_refs(a, names) for a in expr.kwargs.values())
        )
    if isinstance(expr, ir.StrJoin):
        return any(_refs(p, names) for p in expr.parts)
    if isinstance(expr, ir.Collection):
        return any(_refs(i, names) for i in expr.items)
    if isinstance(expr, ir.Unknown):
        return any(_refs(c, names) for c in expr.children)
    return False


def _is_transform_expr(expr: ir.Expr | None, names: set[str]) -> bool:
    """A *transform* of the input: an expression built from `names` that is not
    a bare read. `code.replace(...)`, `f"{code}"`, `wrap(code)` all transform;
    a bare `code` (passthrough) does not."""
    return not isinstance(expr, ir.VarRef) and _refs(expr, names)


def _returns_transformed_input(fn: ir.FuncDef) -> bool:
    """Does the function return a *transformed* copy of one of its parameters?

    This is the cosmetic-sanitizer shape (the Vanna `_sanitize_plotly_code`
    pattern): mutate the model output with `.replace(...)` / f-strings, then
    hand the mutated value to the sink. Returning a parameter *unchanged* after
    a real check is not caught here - that is genuine validate-and-passthrough.
    """
    params = set(fn.params)
    if not params:
        return False
    assigns = [s for s in _walk_stmts(fn.body) if isinstance(s, ir.Assign)]
    tainted = set(params)  # names carrying input-derived data
    transformed: set[str] = set()  # names carrying a *transformed* input value
    # Fixpoint (small bodies): _walk_stmts is not source-ordered, so iterate
    # until the transformed/tainted sets stop growing.
    changed = True
    while changed:
        changed = False
        for a in assigns:
            # An augmented assignment (`code += x`) lowers to a target key
            # prefixed `+` ("union with prior taint", ir/model.py Assign).
            # `code += x` always transforms `code` when `code` already
            # carries input-derived data - its new value folds in the old
            # one regardless of what `x` is (`code += ""` still transforms a
            # tainted `code`, even though "" itself references nothing
            # tainted). Without treating augmented targets specially, `+code`
            # never entered `transformed`/`tainted` and the cosmetic
            # transform-and-return shape (Vanna CVE-2024-5565) went
            # undetected for the `+=` spelling of an otherwise-identical
            # sanitizer body.
            aug_targets = [t[1:] for t in a.targets if t.startswith("+")]
            plain_targets = [t for t in a.targets if not t.startswith("+")]
            for t in aug_targets:
                if t in tainted and t not in transformed:
                    transformed.add(t)
                    changed = True
            if _is_transform_expr(a.value, tainted):
                for t in plain_targets:
                    if t not in transformed:
                        transformed.add(t)
                        tainted.add(t)
                        changed = True
            elif _refs(a.value, tainted):  # passthrough copy: y = x
                for t in plain_targets:
                    if t not in tainted:
                        tainted.add(t)
                        changed = True
    for s in _walk_stmts(fn.body):
        if isinstance(s, ir.Return) and not s.raises and s.value is not None:
            v = s.value
            if isinstance(v, ir.VarRef) and v.base_var in transformed:
                return True
            if _is_transform_expr(v, tainted):
                return True
    return False


def _body_validates(fn: ir.FuncDef) -> bool:
    """Heuristic: does this function's body look like real validation?

    A sanitizer that transforms its input and returns the transformed value is
    cosmetic and never counts as verified, regardless of any unrelated `raise`
    or guard in the body - unless it also carries a strong allowlist / strict
    validator signal (membership test or re.fullmatch & co). This closes the
    silencing bypass where `code = code.replace(...); if not code: raise;
    return code` was treated as validated.

    Otherwise the signals are: a membership test anywhere (`x in ALLOWED`), a
    guard branch (an if that raises/returns, or an enum-literal membership), a
    raise anywhere (validators reject by raising), or a strict-matching
    validator call (re.fullmatch & co).
    """
    strong = fn.has_membership_test or any(p in _VALIDATOR_CALLS for p in _iter_call_paths(fn.body))
    if not strong and _returns_transformed_input(fn):
        return False
    if fn.has_membership_test:
        return True
    for s in _walk_stmts(fn.body):
        if isinstance(s, ir.IfBranch) and (s.terminates or s.literal_membership):
            return True
        if isinstance(s, ir.Return) and s.raises:
            return True
    return any(p in _VALIDATOR_CALLS for p in _iter_call_paths(fn.body))
