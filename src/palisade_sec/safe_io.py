"""Symlink-safe output writes (SF-3, the write side).

Palisade is run from inside repositories it does not trust, and it writes
files at predictable names: `palisade-report.md`, `palisade-fixes.md`,
`palisade-review.md`, `.palisade/baseline.json`. A repository can ship a
symlink at any of those names (or make `.palisade` itself a symlink), and a
plain `Path.write_text` follows it - so `scan . --report` inside a hostile
clone would overwrite `~/.bashrc` or any other file the link points at. 0.5.0
did exactly that.

The read side already refuses symlinks that leave the scan root. This is the
matching rule for writes: never write through a symlink that sits at the
output path itself or at any directory between the boundary and it.
"""

from __future__ import annotations

import os
from pathlib import Path


class UnsafeOutputPath(OSError):
    """Raised instead of writing through a symlink."""


def _ancestors_below(path: Path, boundary: Path) -> list[Path]:
    """Directories strictly between `boundary` and `path` (both absolute).

    Components at or above the boundary are the user's own environment - a
    symlinked home or `/tmp -> /private/tmp` on macOS - and are not checked;
    only what could have come from the scanned tree is.
    """
    try:
        rel = path.parent.relative_to(boundary)
    except ValueError:
        # Outside the boundary: the user named this location explicitly
        # (`--output /elsewhere/x.md`), so only its own directory is checked.
        return [path.parent]
    out = []
    cur = boundary
    for part in rel.parts:
        cur = cur / part
        out.append(cur)
    return out


def write_output(path: Path, text: str, boundary: Path | None = None) -> None:
    """Write `text` to `path`, refusing to follow a symlink anywhere below
    `boundary` (default: the current directory).

    Missing directories are created, but never through a symlink, and the
    final open uses O_NOFOLLOW so a link swapped in after the check is still
    refused rather than followed.
    """
    boundary = (boundary or Path.cwd()).absolute()
    target = path if path.is_absolute() else Path.cwd() / path

    try:
        target.parent.relative_to(boundary)
    except ValueError:
        # Explicit location outside the boundary: create its parents as asked.
        target.parent.parent.mkdir(parents=True, exist_ok=True)

    for d in _ancestors_below(target, boundary):
        if d.is_symlink():
            raise UnsafeOutputPath(
                f"refusing to write {path}: {d} is a symlink. A scanned repository "
                "may plant links at Palisade's output paths; remove it or choose "
                "another location."
            )
        if not d.exists():
            d.mkdir()
        elif not d.is_dir():
            raise UnsafeOutputPath(f"refusing to write {path}: {d} is not a directory")

    if target.is_symlink():
        raise UnsafeOutputPath(
            f"refusing to write {path}: it is a symlink. A scanned repository may "
            "plant links at Palisade's output paths; remove it or choose another "
            "location."
        )

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o644)
    except OSError as exc:
        # ELOOP: a symlink appeared between the check and the open.
        if target.is_symlink():
            raise UnsafeOutputPath(f"refusing to write {path}: it is a symlink") from exc
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
