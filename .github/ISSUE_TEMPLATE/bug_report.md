---
name: Bug report
about: A crash, wrong output, or broken behavior (not a false positive/negative)
title: "[BUG] "
labels: bug
---

<!--
For "it flagged something safe" use the False positive template; for "it missed
a real path" use the Missed finding template. This one is for everything else:
crashes, bad parses, CLI/flag issues, SARIF/JSON output problems, install issues.
-->

## What happened

A clear description of the bug.

## Steps to reproduce

```
# exact command(s)
palisade-sec scan ...
```

## Expected vs actual

- Expected:
- Actual (paste output / traceback):

```
<output or traceback>
```

## Environment

- Palisade version: `palisade-sec --version`
- Python version: `python --version`
- OS:
- Install: `uvx` / `pip` (+ `[js]` extra?)
