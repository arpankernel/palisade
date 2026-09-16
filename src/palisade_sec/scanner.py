"""Scan orchestration: config, file discovery, frontend -> engine.

SAFETY (SF-1..SF-3): scanning only reads source text and parses it with
`ast.parse`. It never imports or executes scanned code, makes no network
calls, and writes nothing (the CLI owns the only writes: `.palisade/` and an
explicitly requested report file).
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, ValidationError

from palisade_sec import ir
from palisade_sec.engine import Engine, Finding
from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.rules import load_rules
from palisade_sec.suppress import (
    Suppression,
    apply_suppressions,
    parse_suppressions,
    stale_suppressions,
)


class Frontend(Protocol):
    """What the scanner needs from a language frontend."""

    def lower_file(self, path: str, rel_path: str, source: str) -> ir.Module | ParseFailure: ...


PY_EXTENSIONS = (".py", ".pyi")
JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")

ALWAYS_EXCLUDE_DIRS = {
    ".venv",
    "venv",
    ".git",
    "site-packages",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
    ".palisade",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    ".eggs",
}


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paths_ignore: list[str] = []
    include_tests: bool = False
    max_hops: int = 3
    rules_dir: str | None = None
    # Library mode: treat parameters of public functions as untrusted sources.
    assume_params_untrusted: bool = False
    # Resource caps (self-DoS protection; a hostile file must never take the
    # scan down): files larger than this are skipped with a warning, and a
    # soft wall-clock budget skips remaining files once exceeded.
    max_file_bytes: int = 2_000_000
    max_scan_seconds: float | None = None


def load_config(root: Path, config_file: str | None) -> tuple[ScanConfig, list[str]]:
    """Config from --config, .palisade.toml, or pyproject [tool.palisade].
    Invalid config -> warning + defaults, never a crash (MT-3, RB-4)."""
    warnings: list[str] = []
    candidates: list[tuple[Path, str | None]] = []
    if config_file:
        candidates.append((Path(config_file), None))
    candidates.append((root / ".palisade.toml", None))
    candidates.append((root / "pyproject.toml", "palisade"))
    for path, tool_key in candidates:
        if not path.is_file():
            if config_file and path == Path(config_file):
                warnings.append(f"config file not found, using defaults: {path}")
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
            warnings.append(f"invalid config skipped: {path}: {exc}")
            continue
        if tool_key:
            data = data.get("tool", {}).get(tool_key)
            if data is None:
                continue
        try:
            return ScanConfig.model_validate(data), warnings
        except ValidationError as exc:
            warnings.append(f"invalid config skipped: {path}: {exc.errors()[0].get('msg', exc)}")
    return ScanConfig(), warnings


def _load_gitignore(root: Path) -> list[str]:
    gi = root / ".gitignore"
    patterns: list[str] = []
    if gi.is_file():
        try:
            for line in gi.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                patterns.append(line.rstrip("/"))
        except OSError:
            pass
    return patterns


def _ignored(rel: str, patterns: list[str]) -> bool:
    parts = rel.split("/")
    for pat in patterns:
        if "/" in pat:
            if fnmatch.fnmatch(rel, pat.lstrip("/")) or fnmatch.fnmatch(
                rel, pat.lstrip("/") + "/*"
            ):
                return True
        else:
            if any(fnmatch.fnmatch(p, pat) for p in parts):
                return True
    return False


def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if name == "conftest.py":
        return True
    if any(p in ("tests", "test") for p in parts[:-1]):
        return True
    return name.startswith("test_") or name.endswith("_test.py")


def collect_files(root: Path, cfg: ScanConfig) -> list[Path]:
    if root.is_file():
        return [root]
    gitignore = _load_gitignore(root)
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        dirnames[:] = [
            d
            for d in sorted(dirnames)
            if d not in ALWAYS_EXCLUDE_DIRS
            and not _ignored(f"{rel_dir}/{d}".lstrip("./"), gitignore)
            and not _ignored_by_cfg(f"{rel_dir}/{d}".lstrip("./"), cfg)
        ]
        for fname in sorted(filenames):
            if not fname.endswith(PY_EXTENSIONS + JS_EXTENSIONS):
                continue
            rel = f"{rel_dir}/{fname}".lstrip("./").lstrip("/")
            if rel_dir == ".":
                rel = fname
            if _ignored(rel, gitignore) or _ignored_by_cfg(rel, cfg):
                continue
            if not cfg.include_tests and _is_test_path(rel):
                continue
            files.append(Path(dirpath) / fname)
    return files


def _ignored_by_cfg(rel: str, cfg: ScanConfig) -> bool:
    return any(
        fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat.rstrip("/") + "/*")
        for pat in cfg.paths_ignore
    )


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped: list[str] = field(default_factory=list)  # parse failures etc.
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # findings silenced by inline `palisade: ignore` comments
    suppressed: list[dict] = field(default_factory=list)
    # Untrusted sources the engine minted. Zero means the scan was never
    # challenged - taint had nowhere to start - so "no findings" is not
    # evidence the code is clean. See EngineResult.sources_found.
    sources_found: int = 0


def run_scan(
    target: Path,
    config_file: str | None = None,
    rules_dir: str | None = None,
    max_hops: int | None = None,
    assume_params_untrusted: bool | None = None,
) -> ScanResult:
    result = ScanResult()
    root = target.resolve()
    cfg, cfg_warnings = load_config(root if root.is_dir() else root.parent, config_file)
    result.warnings.extend(cfg_warnings)

    rules_result = load_rules(rules_dir or cfg.rules_dir)
    result.warnings.extend(rules_result.warnings)
    if not rules_result.rules:
        result.warnings.append("no valid rules loaded; nothing to scan for")
        return result

    frontends: dict[str, Frontend] = {ext: PythonFrontend() for ext in PY_EXTENSIONS}
    js_frontend = None
    js_unavailable = False
    try:
        from palisade_sec.frontends.tree_sitter_js import AVAILABLE, JavaScriptFrontend

        if AVAILABLE:
            js_frontend = JavaScriptFrontend()
        else:
            js_unavailable = True
    except ImportError:
        js_unavailable = True
    if js_frontend is not None:
        frontends.update({ext: js_frontend for ext in JS_EXTENSIONS})

    base = root if root.is_dir() else root.parent
    resolved_base = base.resolve()
    modules = []
    js_skipped = 0
    suppressions: dict[str, dict[int, Suppression]] = {}
    started = time.monotonic()
    for path in collect_files(root, cfg):
        rel = path.relative_to(base).as_posix()
        if cfg.max_scan_seconds is not None and time.monotonic() - started > cfg.max_scan_seconds:
            result.warnings.append(
                f"scan time budget ({cfg.max_scan_seconds}s) exceeded; remaining files skipped"
            )
            break
        ext = path.suffix.lower()
        frontend = frontends.get(ext)
        if frontend is None:
            if js_unavailable and ext in JS_EXTENSIONS:
                js_skipped += 1
            continue
        # SF-3: never read outside the target. A symlink inside the tree that
        # resolves outside the scan root is skipped, not followed.
        try:
            resolved = path.resolve()
            if root.is_dir() and not resolved.is_relative_to(resolved_base):
                result.skipped.append(f"{rel}: symlink escapes the scan root, skipped")
                continue
            size = path.stat().st_size
        except OSError as exc:
            result.skipped.append(f"{rel}: unreadable ({exc})")
            continue
        if size > cfg.max_file_bytes:
            result.skipped.append(
                f"{rel}: exceeds max_file_bytes ({size} > {cfg.max_file_bytes}), skipped"
            )
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            result.skipped.append(f"{rel}: unreadable ({exc})")
            continue
        source = raw.decode("utf-8", errors="replace")
        lowered = frontend.lower_file(str(path), rel, source)
        if isinstance(lowered, ParseFailure):
            result.skipped.append(f"{rel}: parse error, file skipped ({lowered.reason})")
            continue
        lowered.content_hash = hashlib.sha256(raw).hexdigest()[:16]
        found = parse_suppressions(source)
        if found:
            suppressions[rel] = found
        modules.append(lowered)
        result.files_scanned += 1
    if js_skipped:
        result.notes.append(
            f"{js_skipped} JS/TS file(s) skipped - install the JS frontend with "
            "`pip install 'palisade-sec[js]'` (or `uvx --with 'palisade-sec[js]' ...`)"
        )

    engine = Engine(
        modules,
        rules_result.rules,
        max_hops=max_hops or cfg.max_hops,
        assume_params_untrusted=(
            cfg.assume_params_untrusted
            if assume_params_untrusted is None
            else assume_params_untrusted
        ),
    )
    engine_result = engine.run()
    kept, suppressed = apply_suppressions(engine_result.findings, suppressions)
    result.findings = kept
    result.suppressed = suppressed
    result.sources_found = engine_result.sources_found
    result.notes.extend(engine_result.notes)
    if suppressed:
        result.notes.append(
            f"{len(suppressed)} finding(s) silenced by inline `palisade: ignore` comments"
        )
    stale = stale_suppressions(suppressions)
    if stale:
        result.notes.append(
            "stale `palisade: ignore` comment(s) matching nothing: " + ", ".join(stale[:10])
        )
    return result
