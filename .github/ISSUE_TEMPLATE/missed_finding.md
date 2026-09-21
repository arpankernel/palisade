---
name: Missed finding (false negative)
about: A real untrusted-input -> LLM -> sink path Palisade did not flag
title: "[FN] "
labels: false-negative
---

<!--
Recall is tracked honestly and stated publicly (currently 0.667 on the pinned
corpus, with the one known miss documented). A reproducible miss is valuable.
-->

## The path that should have been flagged

Where does untrusted input enter, where does it reach the model, and what
dangerous sink does the model output reach?

- source (untrusted input): `file:line`
- LLM call: `file:line`
- sink (exec / shell / SQL / HTTP / tool): `file:line`

## Minimal reproducer

```python
# smallest code that has the path but produces no finding
```

## What Palisade did instead

```
<paste `palisade-sec scan <path> --all` output>
```

## Environment

- Palisade version: `palisade-sec --version`
- Language: Python / JavaScript / TypeScript
- Framework (if relevant): LangChain / LlamaIndex / OpenAI Agents SDK / LangGraph / CrewAI / other
