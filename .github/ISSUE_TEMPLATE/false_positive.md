---
name: False positive
about: Palisade flagged something that is not a real prompt-injection path
title: "[FP] "
labels: false-positive
---

<!--
Precision is the product: every confirmed false positive becomes a permanent
must-stay-silent regression test. Thank you for reporting one.
-->

## The finding Palisade reported

Paste the finding (rule id, file:line, severity). `--json` output is ideal:

```
<paste `palisade-sec scan <path> --json` for the finding here>
```

## The code it flagged

A minimal snippet (or a link to the public file + line) that reproduces it:

```python
# smallest code that still triggers the finding
```

## Why it is not exploitable

What breaks the untrusted-input -> LLM -> sink path here? (e.g. the value is
validated/cast, the prompt is constant, the sink is parameterized, there is no
real source.)

## Environment

- Palisade version: `palisade-sec --version`
- Language: Python / JavaScript / TypeScript
- Install: `uvx` / `pip` (+ `[js]` extra?)
