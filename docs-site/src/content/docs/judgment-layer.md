---
title: "Judgment layer (optional)"
description: "Which commands are keyless vs bring-your-own-endpoint, and how to set up the optional AI-judgment layer with TypeSafe or any OpenAI-compatible endpoint."
---

Palisade has two layers, and most people only ever need the first.

- **The offline core** - `scan`, `map`, `baseline`, `fix`, and `redteam`
  synthesis. No API key, no account, no network calls, no telemetry. This is
  what `uvx palisade-sec scan .` runs, and it is the whole tool for most users.
- **The judgment layer** - `audit`, `redteam --execute`, and the AI-judged part
  of `review`. These ask a language model to judge findings the static analyzer
  already grounded (how exploitable is this path, can this tool take an
  irreversible action). They need an endpoint you configure. Nothing is sent
  anywhere until you set one up.

## Which commands need a key?

| Command | Needs a judgment endpoint? |
|---|---|
| `scan` (the headline command) | **No** - offline, keyless |
| `map` | **No** |
| `fix` | **No** |
| `baseline` | **No** |
| `redteam` (synthesis - the default) | **No** |
| `audit` | **Yes** |
| `review` | Only for the AI-judged layer. Without a key it runs **taint-only** and says so |
| `redteam --execute` | **Yes** |

You are not locked into one vendor. The judgment layer speaks **TypeSafe** (the
default, which returns calibrated answers) **or any OpenAI-compatible endpoint**
(OpenAI, a local model, an internal gateway).

## Setup (about two minutes)

### 1. Install the extra

```bash
pip install 'palisade-sec[judge]'
# or
uv add 'palisade-sec[judge]'
```

### 2. Create a `.env`

Copy the template and fill in one backend:

```bash
cp .env.example .env
```

**Option A - TypeSafe (default, calibrated):**

```bash
PALISADE_JUDGE_BACKEND=typesafe
PALISADE_JUDGE_ENDPOINT=https://api.typesafe.ai   # default, can omit
PALISADE_JUDGE_MODEL=jev-latest                   # default, can omit
TYPESAFE_API_KEY=...                              # your key
```

Get a key at [typesafe.ai](https://typesafe.ai). TypeSafe returns typed,
calibrated answers with confidence, so Palisade marks its judgments **verified** -
they can inform a BLOCK decision or a Critical posture.

**Option B - any OpenAI-compatible endpoint:**

```bash
PALISADE_JUDGE_BACKEND=openai_compatible
PALISADE_JUDGE_ENDPOINT=https://api.openai.com/v1   # required
PALISADE_JUDGE_MODEL=gpt-4o-mini                     # required
PALISADE_JUDGE_API_KEY=...                           # your key
```

A generic endpoint is validated against a strict schema and treated as
**best-effort / unverified**: it can flag and downgrade findings, but it can
never emit a BLOCK or raise a Critical posture on judgment alone.

### 3. Run a judged command

```bash
palisade-sec audit .
# or
palisade-sec review .
```

If no key is configured, `audit` stops with a clear message and `review` falls
back to taint-only (and tells you). The offline core keeps working regardless.

## What stays honest about this layer

- **Your keys stay yours.** They are read from the environment only, and never
  logged or included in error messages.
- **The core never calls out.** Only the three judged commands above touch the
  network; `scan` / `map` / `fix` / `baseline` never do.
- **Judged signals are advisory - they do not gate CI.** `--ci` gates only on
  deterministic taint findings; a model's judgment never fails your build on its
  own. The judged layer has a preliminary seed-corpus calibration and is labeled
  as such until scored on a full benchmark.
- **An unverified backend cannot manufacture severity.** It downgrades to REVIEW
  rather than BLOCK, and cannot raise a Critical posture alone.

## Configuration reference

| Variable | Meaning |
|---|---|
| `PALISADE_JUDGE_BACKEND` | `typesafe` (default) or `openai_compatible` |
| `PALISADE_JUDGE_ENDPOINT` | Base URL. Defaults to the TypeSafe API for `typesafe`; required for `openai_compatible` |
| `PALISADE_JUDGE_MODEL` | Model id. Defaults to `jev-latest` for `typesafe`; required for `openai_compatible` |
| `TYPESAFE_API_KEY` | Key for the `typesafe` backend |
| `PALISADE_JUDGE_API_KEY` | Key for the `openai_compatible` backend |

`redteam --execute` additionally reads `PALISADE_REDTEAM_TARGET` (the endpoint
you fire attacks at) and `PALISADE_REDTEAM_KEY`. It drives the target **you**
provide, in your environment - Palisade never executes your code.

See the [CLI reference](cli-reference.md) for every command and flag.
