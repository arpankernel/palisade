"""IR node definitions.

Design constraints:
- Language-agnostic: nothing here references Python's `ast` types. A JS/TS
  frontend must be able to emit the same nodes.
- Small on purpose: only what taint propagation needs. Anything a frontend
  cannot express folds into `Unknown`, which propagates the taint of its
  children (conservative but bounded).

Expressions carry a `path` where a dotted name is known (e.g. the call target
`subprocess.run` after import-alias resolution). Rules match on these paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# C0/C1 control characters (tab kept) and Unicode bidi overrides. Scanned code
# is untrusted, and snippets and file paths are echoed straight to the
# analyst's terminal and into shared reports. A raw ESC in a string literal
# would otherwise let a scanned repo clear lines, recolour or rewrite
# Palisade's own output (e.g. paint a fake "no findings"), and a newline in a
# filename would break report structure; bidi overrides ("Trojan Source",
# CVE-2021-42574) would make the shown code differ from the real code.
_UNSAFE_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def neutralize(text: str) -> str:
    """Replace control and bidi characters with a visible escape (`\\x1b`,
    `\\u202e`) so they are shown, never interpreted."""
    if not _UNSAFE_CHARS.search(text):
        return text
    return _UNSAFE_CHARS.sub(
        lambda m: (
            f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100 else f"\\u{ord(m.group()):04x}"
        ),
        text,
    )


@dataclass(frozen=True)
class Loc:
    """A source location. `snippet` is the stripped source line."""

    file: str
    line: int
    col: int = 0
    snippet: str = ""

    def __post_init__(self) -> None:
        # Every frontend builds its locations here, so this is the one place
        # untrusted text is made safe to print (terminal, markdown, SARIF).
        object.__setattr__(self, "file", neutralize(self.file))
        object.__setattr__(self, "snippet", neutralize(self.snippet))


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------


@dataclass
class Expr:
    loc: Loc


@dataclass
class Const(Expr):
    """A literal constant. Never tainted."""

    value: object = None


@dataclass
class VarRef(Expr):
    """A read of a local/global name, import-alias resolved.

    `path` is the dotted path when the read is an attribute chain rooted at a
    name: `resp.choices` -> path "resp.choices", base_var "resp".
    """

    path: str = ""
    base_var: str = ""


@dataclass
class Member(Expr):
    """Attribute or subscript access on a non-trivial base expression.

    Taint of the whole is the taint of `base`. `path` is set when a dotted
    path could still be computed (for source matching), else "".
    """

    base: Expr | None = None
    path: str = ""


@dataclass
class Call(Expr):
    """A call. `func_path` is the dotted call target after alias resolution.

    `receiver` is the object expression a method was called on (for taint
    propagation through e.g. `tainted.strip()`); None for plain calls.
    """

    func_path: str = ""
    receiver: Expr | None = None
    args: list[Expr] = field(default_factory=list)
    kwargs: dict[str, Expr] = field(default_factory=dict)
    star_args: list[Expr] = field(default_factory=list)


@dataclass
class StrJoin(Expr):
    """String construction: f-string, %, .format, +, .join. Taint = union."""

    parts: list[Expr] = field(default_factory=list)


@dataclass
class Collection(Expr):
    """dict/list/tuple/set/comprehension result. Taint = union of items."""

    items: list[Expr] = field(default_factory=list)


@dataclass
class Unknown(Expr):
    """Anything else. Taint = union of children (conservative)."""

    children: list[Expr] = field(default_factory=list)


# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------


@dataclass
class Stmt:
    loc: Loc


@dataclass
class Assign(Stmt):
    """Assignment to one or more variable keys.

    Target keys are plain names ("x") or self-attributes ("self.x"). Tuple
    unpacking produces several keys sharing the value's taint.
    """

    targets: list[str] = field(default_factory=list)
    value: Expr | None = None


@dataclass
class ExprStmt(Stmt):
    value: Expr | None = None


@dataclass
class Return(Stmt):
    value: Expr | None = None
    raises: bool = False  # this "return" is actually a raise


@dataclass
class IfBranch(Stmt):
    """`test_names` = dotted names read in the test; `test_calls` = call paths
    in the test. The engine uses these for sanitizer / partial-defense guard
    recognition. `terminates` = the body unconditionally returns/raises,
    meaning the guard filters the fall-through path.
    """

    test: Expr | None = None
    test_names: list[str] = field(default_factory=list)
    test_calls: list[str] = field(default_factory=list)
    body: list[Stmt] = field(default_factory=list)
    orelse: list[Stmt] = field(default_factory=list)
    terminates: bool = False
    negated: bool = False  # test was `x not in Y` / `not f(x)`
    literal_membership: bool = False  # test was `x in ("a", "b", ...)` (enum guard)
    guard_var: str = ""  # the compared variable for membership tests
    membership_name: str = ""  # dotted name of the collection in `x in NAME`


@dataclass
class ForLoop(Stmt):
    target_keys: list[str] = field(default_factory=list)
    iter: Expr | None = None
    body: list[Stmt] = field(default_factory=list)


@dataclass
class WhileLoop(Stmt):
    body: list[Stmt] = field(default_factory=list)


@dataclass
class TryBlock(Stmt):
    body: list[Stmt] = field(default_factory=list)
    handlers: list[list[Stmt]] = field(default_factory=list)
    finalbody: list[Stmt] = field(default_factory=list)


@dataclass
class WithBlock(Stmt):
    items: list[tuple[str | None, Expr]] = field(default_factory=list)
    body: list[Stmt] = field(default_factory=list)


# --------------------------------------------------------------------------
# Definitions
# --------------------------------------------------------------------------


@dataclass
class FuncDef:
    name: str
    qualname: str  # "module_stem.ClassName.method" or "module_stem.func"
    params: list[str]
    body: list[Stmt]
    loc: Loc
    class_name: str | None = None
    is_test: bool = False
    # True when the body tests the input FOR membership in a collection that is
    # not itself the input: an allowlist (`code in ALLOWED`,
    # `ALLOWED.includes(code)`). Searching the input for bad strings
    # (`"import" in code`, `code.includes("os.")`) is a denylist and does NOT
    # set this - denylists are bypassable and must never silence a finding.
    has_allowlist_membership: bool = False
    # Dotted paths of decorators (alias-resolved), e.g. "app.post" - used to
    # recognize web-framework entry points whose params are untrusted.
    decorators: list[str] = field(default_factory=list)


@dataclass
class Module:
    path: str  # absolute file path
    rel_path: str  # path relative to scan root (display + fingerprints)
    stem: str  # import name relative to scan root, e.g. "pkg.utils"
    functions: list[FuncDef] = field(default_factory=list)
    toplevel: FuncDef | None = None  # module-level statements as pseudo-func
    imports: dict[str, str] = field(default_factory=dict)  # alias -> dotted path
    # class name -> base-class dotted paths (alias-resolved), for
    # class-hierarchy method resolution.
    class_bases: dict[str, list[str]] = field(default_factory=dict)
    # sha256[:16] of the raw file bytes - the seam for future incremental
    # scanning / caching (unused by the engine itself).
    content_hash: str = ""
