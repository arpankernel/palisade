---
name: Rule / framework support request
about: Ask for coverage of a new sink, source, LLM signature, or framework
title: "[RULE] "
labels: enhancement
---

<!--
Rules are plain YAML (sources, llm_signatures, sinks, sanitizers) and adding
coverage is usually a data change, not an engine change. You can often write it
yourself and pass `--rules ./dir`; see docs/rules-reference. Open this if the
shape needs engine support or you think it should be builtin.
-->

## What is not covered

The framework / SDK / sink / source pattern Palisade should recognize.

## An example of the shape

```python
# how the LLM call / sink / source looks in real code
```

## Why it belongs in the builtin rules

Is this a widely used framework, a real CVE class, or a common deployment
pattern? Links to the library and any relevant advisory help.

## Have you tried a custom rule?

`--rules ./dir` with a YAML rule (see docs/rules-reference). If it did not work,
what happened?
