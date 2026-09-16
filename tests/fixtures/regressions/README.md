# False-positive regression fixtures

Phase 0 requires that **every false positive anyone reports becomes a
permanent must-stay-silent test**, so precision only ever ratchets upward.

Each `.py` / `.js` file in this directory is a minimal reproduction of code
that Palisade must **not** flag. `tests/test_fp_regressions.py` discovers
them automatically and asserts zero findings for each, so adding a case is
just adding a file.

## Adding a case

1. Reduce the reported code to the smallest snippet that still misfires.
2. Drop it here as `<short-name>.py`, with a header comment explaining why
   it is safe and where it came from (issue number or corpus repo).
3. Run `uv run pytest tests/test_fp_regressions.py` - it should fail.
4. Fix the rule or the engine until it passes. Never fix it by weakening an
   unrelated assertion.

A case is only allowed to leave this directory if the code it represents is
genuinely dangerous after all, and that reversal belongs in the commit
message.
