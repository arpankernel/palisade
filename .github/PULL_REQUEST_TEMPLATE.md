<!-- Thanks for contributing to Palisade. Keep the gate green. -->

## What and why

Briefly: what does this change and why.

## Type

- [ ] Bug fix
- [ ] New rule / framework coverage (YAML data change)
- [ ] Engine / feature
- [ ] Docs / website
- [ ] False-positive regression fixture (precision hardening)

## Checklist

- [ ] The gate passes locally: `ruff check . && ruff format --check src tests scripts corpus && mypy src/palisade_sec && uv run pytest -q`
- [ ] Precision holds: `python scripts/precision.py corpus/manifest.yaml`
- [ ] A precision-affecting change adds a fixture (a fixed false positive becomes a permanent must-stay-silent test)
- [ ] Public-facing behavior is documented (README / docs / CHANGELOG) if relevant

## Notes

Anything reviewers should know (trade-offs, follow-ups, out-of-scope).
