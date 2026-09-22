"""Load and validate YAML rules. Invalid rules are reported and skipped -
never a crash (MT-3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from palisade_sec.rules.schema import Rule

BUILTIN_RULES_DIR = Path(__file__).parent


@dataclass
class RuleLoadResult:
    rules: list[Rule] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_rules(extra_dir: str | None = None) -> RuleLoadResult:
    result = RuleLoadResult()
    dirs = [BUILTIN_RULES_DIR]
    if extra_dir:
        dirs.append(Path(extra_dir))
    seen_ids: set[str] = set()
    for d in dirs:
        if not d.is_dir():
            result.warnings.append(f"rules directory not found, skipped: {d}")
            continue
        for f in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
                result.warnings.append(f"invalid rule file skipped: {f.name}: {exc}")
                continue
            if not isinstance(data, dict):
                result.warnings.append(f"invalid rule file skipped: {f.name}: not a mapping")
                continue
            try:
                rule = Rule.model_validate(data)
            except ValidationError as exc:
                result.warnings.append(
                    f"invalid rule file skipped: {f.name}: {exc.errors()[0].get('msg', exc)}"
                )
                continue
            if rule.id in seen_ids:
                # later dirs (user-provided) override builtins
                result.rules = [r for r in result.rules if r.id != rule.id]
            seen_ids.add(rule.id)
            result.rules.append(rule)
    return result
