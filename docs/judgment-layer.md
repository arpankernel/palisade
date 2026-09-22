# The judgment layer (optional)

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
| `audit` | **Yes** (exits `2` with a hint without one) |
| `review` | Only for the AI-judged layer. Without the extra or a key it runs **taint-only** and says so |
| `redteam --execute` | **Yes** (exits `2` with a hint without one) |

You are not locked into one vendor. The judgment layer speaks **TypeSafe** (the
default, whose answers Palisade treats as verified) **or any OpenAI-compatible endpoint**
(OpenAI, a local model, an internal gateway).

## Setup (about two minutes)

### 1. Install the extra

```bash
pip install 'palisade-sec[judge]'
# or
uv add 'palisade-sec[judge]'
# or one-shot, nothing installed permanently
uvx --from 'palisade-sec[judge]' palisade-sec review .
```

Without the extra, `audit` and `redteam --execute` exit `2` with an install
hint, and `review` runs taint-only.

### 2. Create a `.env`

Palisade reads the judge settings from the environment, or from a `.env` in
the current working directory (the directory you run `palisade-sec` from, or a
parent of it). Variables already set in the environment win over `.env`.
Create `.env` there from this template and fill in one backend:

```bash
# Palisade judgment layer configuration.
#
# ONLY the bring-your-own-endpoint commands (audit, review, redteam execution)
# read this. The offline core (scan, map, baseline, fix) never calls out and
# never needs any of it.
#
# Copy to `.env` in the directory you run palisade-sec from, and fill in. Your
# shell environment wins over this file. Keys are never logged.
#
# For safety, an endpoint set in a .env file is only used with a key from the
# same file: a repository you clone can ship its own .env, and it must not be
# able to send the key from your shell to a server it chose.

# Which adapter to use: typesafe | openai_compatible
PALISADE_JUDGE_BACKEND=typesafe

# Base URL of the judgment endpoint.
#   typesafe          -> defaults to https://api.typesafe.ai
#   openai_compatible -> required, e.g. https://api.openai.com/v1
# PALISADE_JUDGE_ENDPOINT=https://api.typesafe.ai

# Model id.
#   typesafe          -> defaults to jev-latest
#   openai_compatible -> required, e.g. gpt-4o-mini
# PALISADE_JUDGE_MODEL=jev-latest

# Key for PALISADE_JUDGE_BACKEND=typesafe (recommended):
TYPESAFE_API_KEY=

# Key for PALISADE_JUDGE_BACKEND=openai_compatible (best-effort, unverified;
# never blocks on judgment alone):
PALISADE_JUDGE_API_KEY=
```

(From a clone of the repo, `cp .env.example .env` gives you the same file;
the template is not shipped in the installed package.)

**Option A - TypeSafe (default):**

```bash
PALISADE_JUDGE_BACKEND=typesafe
PALISADE_JUDGE_ENDPOINT=https://api.typesafe.ai   # default, can omit
PALISADE_JUDGE_MODEL=jev-latest                   # default, can omit
TYPESAFE_API_KEY=...                              # your key
```

Get a key at [typesafe.ai](https://typesafe.ai). TypeSafe returns typed
answers with confidence, so Palisade marks its judgments **verified** -
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

If the extra or key is missing, `audit` exits `2` with a clear message and
`review` falls back to taint-only (and tells you on stderr). The offline core
keeps working regardless.

## What stays honest about this layer

- **Your keys stay yours.** They are read from the environment only, and never
  logged or included in error messages.
- **The core never calls out.** Only the three judged commands above touch the
  network; `scan` / `map` / `fix` / `baseline` never do.
- **Judged signals are advisory unless you opt in to a gate.** `review --ci`
  gates only on deterministic taint findings; its judged signals never fail your
  build. `audit --ci` is the one explicit opt-in gate on judged output: it exits
  `1` on a BLOCK decision (which an unverified backend cannot produce on
  judgment alone). Calibration is preliminary: measured on a 10-case seed
  corpus (n=4 to 6 per signal), not a benchmark result; the judged layer stays
  advisory.
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
