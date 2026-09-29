# Connect GitHub, Slack and an LLM (from the terminal)

Palisade is a CLI product. There is no dashboard, no account, and no
service of ours between you and your code: you connect what you want from
the terminal, and the credentials stay on your machine.

```bash
palisade-sec connect github     # open pull requests with the fix plan
palisade-sec connect slack      # post findings to a channel
palisade-sec connect llm        # the optional judgment layer (audit, review)
palisade-sec connections        # what is connected, redacted
palisade-sec disconnect slack   # remove one
```

Connecting is optional. `scan`, `map`, `baseline` and `fix` never use any
of it: they stay offline and keyless, and a test in the suite fails if the
scanner so much as imports the code that can reach the network.

## Where credentials are stored

With the `keyring` extra installed, in your operating system's keychain
(macOS Keychain, Windows Credential Manager, Linux Secret Service):

```bash
pip install 'palisade-sec[keyring]'
```

Without it, in `~/.config/palisade/credentials.toml`, created `0600`
inside a `0700` directory. If anything loosens those permissions, Palisade
refuses to read the file and tells you to fix it rather than using a
secret other users on the machine can read.

The environment always wins over stored values, so CI is unaffected by
whatever a developer has connected locally. `palisade-sec connections`
shows the source of each credential, and values are always redacted.

## GitHub

```bash
palisade-sec connect github
```

If the [GitHub CLI](https://cli.github.com) is installed and logged in,
Palisade offers to reuse its token: nothing else to set up. Otherwise it
runs the OAuth device flow (it prints a code, you approve it in the
browser). You can also pass a token directly with `--token`, or `--token -`
to be prompted without it appearing in your shell history.

The token is verified against the GitHub API before it is stored, and a
token that cannot open pull requests is rejected with the reason. In CI,
set `GITHUB_TOKEN` and skip all of this.

### Open a pull request with the fix plan

```bash
palisade-sec pr .                       # draft PR with the remediation plan
palisade-sec pr . --dry-run             # show what it would do
palisade-sec pr . --baseline .palisade/baseline.json   # only new findings
```

It scans, generates the same plan as `palisade-sec fix` (a guardrail and a
regression test per finding), and opens a **draft** pull request
containing it. The branch name is derived from the findings, so re-running
updates that same pull request instead of opening another.

It is a plan, not a patch. Palisade does not edit your source: the
guardrails are for you to place and adapt, and the tests are the part not
to skip. That is why the PR opens as a draft. Everything goes through the
GitHub API with your token; no local branch is created and no credential
is handed to a subprocess.

## Slack

Create an [incoming webhook](https://api.slack.com/messaging/webhooks) for
the channel you want, then:

```bash
palisade-sec connect slack
palisade-sec notify . --slack
palisade-sec notify . --slack --baseline .palisade/baseline.json  # only new
palisade-sec notify . --slack --dry-run                           # print, don't post
```

`connect slack` posts a test message before storing the webhook, so a
typo fails immediately rather than silently on the next scan. The webhook
URL is a secret (anyone holding it can post to the channel) and is stored
and redacted like a token.

Nothing is ever posted automatically. `notify` is the only command that
posts, and `--dry-run` shows exactly what would be sent.

## LLM provider (optional)

Only the judgment layer uses this: `audit`, and the judged half of
`review`. The scanner does not.

```bash
pip install 'palisade-sec[judge]'
palisade-sec connect llm --provider anthropic      # prompts for the key
palisade-sec connect llm --provider openai_compatible --endpoint https://… --model …
palisade-sec connect llm --provider typesafe
```

The key is checked with one cheap call before it is stored. Anthropic
(Claude) is supported natively; `openai_compatible` covers OpenAI, vLLM,
Ollama's OpenAI mode, LiteLLM and anything else speaking that shape.

Answers from a bring-your-own-endpoint provider are always labelled
unverified and can never block CI on judgment alone. Only the calibrated
TypeSafe service is treated as verified, and even then the judged signals
stay advisory: `review --ci` gates on deterministic taint findings only.

## What is sent where

| Command | Talks to | Sends |
|---|---|---|
| `scan`, `map`, `baseline`, `fix` | nothing | nothing leaves your machine |
| `pr` | api.github.com | the remediation plan, and the finding locations in the PR body |
| `notify --slack` | your webhook | rule ids, file:line, and the sink line, for at most five findings |
| `audit`, `review` (judged) | your configured endpoint | short IR-verified snippets, capped at 200 characters |

Your source is never uploaded in bulk by any of them.
