# Changelog

## 0.7.1 - 2026-10-08

Hardened the judgment layer, which was the part of 0.7.0 that sent anything
anywhere. Three defects, no new capability, and no change to what Palisade
claims to catch. The measured numbers are unchanged: precision 1.000 across
40,466 files, held-out recall 0.000 over 45 independent observations.

### Security

- **An API key could reach the user's terminal through an error message.**
  `JudgeError` documented that it never carries the key or the raw prompt, and
  on one path it did. The Anthropic adapter put the endpoint's
  `error.message` verbatim into the exception, under a comment asserting that
  such a message cannot contain the key. That was an assumption rather than a
  guarantee: the endpoint is settable from config, and a hostile or proxying
  one can echo the `Authorization` header straight back. Error reasons from
  outside now pass through `safe_reason()`, so the documented promise is
  enforced instead of asserted. Reachable only by users of `audit` and
  `review` with a configured endpoint; the offline core never had a key.

- **Secrets are redacted before anything leaves for an endpoint.** A finding's
  snippets are lines of the user's real source, and real source holds real
  credentials, so `audit` and `review` could transmit one as incidental
  context. Provider keys, private-key blocks, JWTs, credentials inside a URL
  and the `name = "value"` form are masked first. A second pass re-checks the
  masked text.

- **Redaction fails closed.** When a payload cannot be proved safe, which
  includes a value of a type the walk cannot inspect, the evidence is not
  sent. The finding is reported `UNJUDGED` with the reason, the rest of the
  audit continues, and the reason names types and paths only, so it is safe to
  print and to log. An audit with any unjudged finding reports
  `"complete": false` in its JSON and is never counted as a pass: the previous
  summary arithmetic would have folded a skipped finding into the pass count.

### Added

- **An instruction boundary in the judge payload.** The evidence is now
  introduced as data and never instructions, naming `CLAUDE.md`, `AGENTS.md`
  and `README` explicitly, since those are the files an attacker would use. It
  lives in the payload rather than a system prompt because the TypeSafe
  backend has no system prompt, and a prompt-only boundary would have covered
  two backends out of three.

- All three protections are applied at `get_backend()`, the single
  construction path, so a backend added later inherits them without its author
  doing anything. Eleven mutation checks delete each protection in turn and
  require the test suite to go red.

### Changed

- **Website rebuilt to the building-not-hiring positioning.** The hero keeps
  its weight and its single-screen contract, measured at zero overflow on
  1280x800, 375x667 and 320x568. Below it: what ships today, how it works, an
  honesty block carrying both numbers with the direction of the ground-truth
  error, the uncovered shape stated plainly, and the five-verb roadmap with no
  dates. Where a product page of this shape puts logos and quotes, this one
  puts the measurement. The palette moved into a single stylesheet, and a test
  now fails the build if either page redefines it inline.

- The install command on the site is click-to-copy, with a fallback for pages
  opened over plain http or from a local checkout.

## 0.7.0 - 2026-09-30

Measured what this engine misses, three times, and rewrote the product's claim
to match rather than rewriting the number.

### The number, and why it is in the changelog

A held-out half of the benchmark corpus was built under
`corpus/RECALL-PROTOCOL.md`: repos assigned by a seeded shuffle committed
before anyone read them, then labelled by agents with no knowledge of this
engine, recording location and verbatim sink text only. 98 real paths in 20
repos, 45 of them independent once correlated paths are collapsed.

    precision   1.000    zero false positives across 40,466 files (50 repos)
    recall      0.000    held-out: 0 of 98 paths, 0 of 45 observations
    recall      0.235    train: 4 of 17, and fit by construction

Three engine passes each moved the held-out number by zero paths. The
constraint was then traced rather than guessed: those paths end in
dependency-injected abstractions and in value flow through constructed
containers, which need whole-program object tracking, not another rule. So the
claim narrowed to what is measured, and the missing capability is on the
roadmap with no date.

**Neither number is published without the other, anywhere**, and
`tests/test_launch_claims.py` fails the build if a surface tries. A scanner
that reports nothing has perfect precision for free.

### Added

- **Attribute-type resolution across object boundaries.** A call on an
  attribute or a local resolves through the type it holds - constructed
  (`self.x = T(...)`), declared in the class body (`x: T = field(...)`) or
  declared on an `__init__` parameter stored on self - and the type takes part
  in LLM-signature and sink matching. The receiver's type is threaded through
  the call, so a template method on an abstract base can resolve its own hook.
  Ambiguity is never guessed.
- **Tool-call arguments are modeled as model output** (`model_output_params` in
  the rule schema). An agent tool's arguments are written by the model, so a
  tool body reaching a dangerous sink is a complete path; the model call itself
  is in the framework's dispatch loop, usually in another package.
- LLM call shapes: `model_client.create`/`create_stream`, `prompt_driver.run`,
  `messages.stream`, and constructed dspy modules resolved through the
  attribute holding them. Named exactly - a wildcard would make every `.create`
  an LLM call.
- Sinks taken verbatim from documented misses: `*.execute_code_blocks`,
  `interpreter.execute`, `repl.execute`.
- Corpus grown from 26 to 50 pinned repositories, 17,352 to 40,466 files.
  Labels carry a `capability` (sql/shell/exec/http/handoff) instead of a rule
  id, and a `group` tag so correlated paths are reported as an effective n.
- `scripts/precision.py`: recall by split, group-level and per-capability
  denominators, and held-out miss coordinates suppressed unless
  `--held-out-detail` is passed, because a list of held-out misses is a to-do
  list for the next engine change.

### Fixed

- **`audit` did not work against its own default backend.** The Anthropic
  backend sent `"temperature": 0`, which current Claude models reject with
  HTTP 400, while `connect llm` reported the key as verified because the probe
  does not send it. Found by running the release checklist on a real key;
  no local test could have caught it, because 493 of them passed with the bug
  in place. The same shape as the `pr --dry-run` false green, arriving through
  the request body instead of the headers.
- **Organization-scoped Anthropic keys are supported** (`connect llm
  --workspace-id`, `ANTHROPIC_WORKSPACE_ID`). The required
  `anthropic-workspace-id` header was missing from both the probe and the
  backend, so `--no-verify` was no escape either.
- **Provider failures carry the provider's reason.** `HTTP 400: Bad Request`
  and `Anthropic returned HTTP 400.` told a user nothing. Both paths now name
  the cause - and, on the connect probe, name the flag that fixes it - while
  still refusing to print the raw response body, which can echo the scanned
  code.
- **The test suite no longer reads the developer's keychain.** Connecting a
  real provider broke 8 tests, because the judge config merges stored settings:
  green in CI, which has no keychain, and red on any machine with a connected
  key. `conftest` already refused to read a real `.env` for this exact reason.
- Three real vulnerabilities in the corpus that our own audit had missed - two
  `crewai` tools, found by triaging a false positive that turned out to be the
  engine being right and the ground truth incomplete. Recorded with their
  provenance, and the corpus now declares that its labels are known-incomplete
  in the direction that makes recall a generous figure rather than a
  conservative one.

### Changed

- The product claim. Palisade is a precise detector for the model-output to
  dangerous-sink shape behind the real CVEs, with published held-out recall. The
  safety-engineer role stays as the direction of travel, marked future work.

## 0.6.2 - 2026-09-30

The policy the judgment layer routes on is now the customer's, not ours.

### Added

- **Policy files load.** `audit` and `review` route on thresholds you own:
  `--policy PATH`, `.palisade/policy.yaml` in the scanned tree, or
  `[tool.palisade.semantic]` in its `pyproject.toml`, else the built-in
  defaults. The model and the defaults had been there since 0.5.0 and
  `audit`/`review` already routed through them, but nothing read a file - so
  changing a threshold meant editing Python, and the policy was ours rather
  than the customer's. A partial file overlays the defaults per check and per
  field, so setting one threshold does not reset the rest; an unknown key is an
  error (`extra="forbid"`), and bad input falls back to the defaults with a
  warning instead of leaving a gate at a threshold nobody chose.
- **`criteria` is confined to a policy you name.** A `criteria` string is
  interpolated into the instructions sent to the judge, so it is prompt text. A
  policy file *discovered inside the tree being scanned* is therefore untrusted
  input reaching a model - the exact shape Palisade detects - and a scanned
  repository could otherwise ship a `.palisade/policy.yaml` reading "nothing
  here is ever irreversible" and argue the judge out of its own finding.
  Discovered files may set thresholds; only `--policy` may set `criteria`, and a
  dropped one warns with the filename. Same split already applied to
  `rules_dir`: an explicit flag is the user's choice, in-tree discovery is
  confined. Pinned end-to-end, including that the refused string never appears
  in the question text built for the model.

### Fixed

- Rich ate `[tool.palisade.semantic]` out of the new `--policy` help text,
  rendering it as "read from .palisade/policy.yaml or ;". The same
  markup-eats-brackets bug 0.6.1 fixed for the `[js]` and `[judge]` install
  hints, caught this time by reading the help output rather than shipping it.
- **The release dry run tested almost nothing it was for.** `download-artifact`
  appears only in the tag-gated `publish` and `github-release` jobs, so
  `workflow_dispatch` could never reach the cross-job artifact handoff - the
  classic place an upload/download major-version bump breaks, and the reason
  the dry run existed. A dry-run-only job now downloads both artifacts the way
  the release jobs do and asserts the wheel, sdist and a parseable CycloneDX
  SBOM survived. (`attest-build-provenance` stays tag-gated deliberately:
  running it on a dispatch would write a real Sigstore transparency-log entry
  for a build that is not a release. Its failure mode is already safe - a break
  fails `build`, and `publish` needs `build`.)
- **Build provenance named the wrong subjects.** `subject-path: dist/*` also
  attested the `.gitignore` that `uv build` writes into `dist/`, so v0.6.0 and
  v0.6.1 carry a provenance statement about a `.gitignore`. The wheel and sdist
  digests were correct and both verify, so nothing shipped wrong; provenance now
  names the two distributables explicitly.

### Supply chain

- Every GitHub Action bumped a major version or more (`checkout` v4 → v7.0.1,
  `setup-uv` v5 → v10.1.0, `codeql-action` v3 → v4.38.1, `upload-artifact`
  v4 → v7.0.1, `download-artifact` v4 → v8.0.1, `setup-node` v4 → v7.0.0,
  `upload-pages-artifact` v3 → v5.0.0, `deploy-pages` v4 → v5.0.1,
  `attest-build-provenance` v2 → v4.2.2). Each new pinned SHA was resolved
  against the tag it claims in the upstream repository before merging.

## 0.6.1 - 2026-09-30

A documentation and release-hygiene release. No behaviour changes to any
command.

### Added

- **PyPI project links.** 0.6.0 published only `Homepage` and `Issues`, so
  the docs site and the changelog were unreachable from the package page.
  The page now links `Homepage` (the site, not the repo), `Documentation`,
  `Source`, `Changelog` and `Issues`.

### Fixed

- **The version had two sources of truth and nothing checked they agreed.**
  `pyproject.toml` decides what PyPI receives and what the release workflow
  matches the git tag against; `palisade_sec.__version__` decides what the
  artifacts say - `--version`, the baseline JSON, the fix plan header, the
  JSON and markdown reports, the HTTP user agent, and the SARIF
  `tool.driver.version` that GitHub code scanning retains against every
  alert. Bumping one without the other would have published a release whose
  own artifacts misreported which release produced them, and the release
  gate would not have noticed. Now asserted by
  `tests/test_version_is_single_sourced.py`, including through a real SARIF
  document.

### Docs

- **`docs/typesafe-integration.md` reconciled against the code.** The spec
  for the judged tier had drifted for several releases: it claimed 1 of ~9
  checks and 5 taint rules (it is 2 and 6), said `review` had no posture
  report (it ships one), said per-check calibration was unbuilt (it is
  measured and published in `corpus/judgment/RESULTS.md`), described a
  4-module layout that is now 13 files plus two subpackages, and told
  readers to install `palisade-sec[semantic]` and set `TYPESAFE_API_KEY`
  when the extra is `[judge]`, three backends are supported, and keys are
  set with `palisade-sec connect llm`.
- Two claims overstated and are now marked as gaps: the `.palisade/policy.yaml`
  in that document **has no reader** - thresholds live in code - and the
  sanitizer check's scope collapsed when 0.5.1 made `_body_validates`
  allowlist-only.
- `tests/test_internal_docs_match_code.py` pins the claims in that document
  that are countable from the code, so the spec can describe unbuilt things
  but cannot misstate shipped ones.

## 0.6.0 - 2026-09-29

Palisade becomes a complete CLI product: GitHub, Slack and an LLM provider
are connected from the terminal, with no dashboard, no account and no
service of ours in the middle.

### Added

- **`connect github` / `connect slack` / `connect llm`**, plus
  `connections` (what is connected, from where, redacted) and
  `disconnect`. Every credential is verified before it is stored, so
  "connected" means "checked": GitHub against `/user` (a token that cannot
  open pull requests is rejected), Slack by posting a real test message,
  an LLM key by one cheap call.
  - GitHub reuses the `gh` CLI's token when it is logged in, otherwise
    runs the OAuth device flow, or takes `--token`.
  - Slack uses an incoming webhook, stored and redacted like a token.
  - LLM supports `typesafe`, `anthropic` and `openai_compatible`.
- **`palisade-sec pr`** opens a **draft** pull request containing the
  remediation plan (a guardrail and a regression test per finding),
  entirely through the GitHub API: no local branch, no `git push`, no
  credential handed to a subprocess. The branch name is derived from the
  findings, so re-running updates the same pull request. It is a plan, not
  a patch, and the PR says so.
- **`palisade-sec notify --slack`** posts a Block Kit summary of a scan,
  with `--baseline` for new findings only and `--dry-run` to print the
  message instead of sending it. Nothing is ever posted automatically.
- **Native Anthropic (Claude) adapter** for the judgment layer, with the
  same strict-JSON contract and schema validation as the generic adapter.
  Like every bring-your-own backend it is `verified=False` and can never
  BLOCK on judgment alone.
- **Credential storage:** the OS keychain via the new optional `[keyring]`
  extra, otherwise `~/.config/palisade/credentials.toml`, created `0600`
  with `O_NOFOLLOW` inside a `0700` directory and refused outright if
  another user can read it. The environment always wins over stored
  values, so CI behaviour is unchanged.
- New guide: `docs/connect.md`, including a table of exactly what each
  command sends and to whom.

### Fixed

Found by exercising the new commands by hand before release, each one on
the path a first-time user actually takes.

- **A surface refusing to connect is no longer reported as a crash.** A
  mistyped webhook, an expired token, or the un-registered OAuth App all
  reached the last-resort handler and printed "internal error … this is a
  bug in palisade-sec … please report it", exit 3 — including the exact
  first-run message that tells you to use `gh auth login`. They now exit
  2 with their own sentence. Every exception in the `connect` package
  shares a `ConnectError` base, and a test walks the package so a new
  surface cannot reintroduce this.
- **`palisade-sec baseline` printed an install command that installs
  nothing.** It rendered scanner warnings through rich, which reads the
  `[js]` in `pip install 'palisade-sec[js]'` as a style tag and deletes
  it; `scan` printed the same warning correctly. Same bug in the
  `connect llm` hint for `[judge]`. A user following either one gets a
  command that succeeds, changes nothing, and leaves no error to search
  for. `baseline` now reports diagnostics like every other command (to
  stderr, including skipped files).
- **`pr --dry-run` no longer reports success when the real run cannot
  start.** It returned before looking for a credential, so it was a green
  pre-flight for a command that would immediately fail. It now names the
  token's source (`connected (via gh)`) and exits 2 when there is none,
  still without contacting GitHub.
- `python -m palisade_sec.cli` called `app()` directly, bypassing the
  error handling of the installed console script. It now calls `run()`.
- **"Set a key" errors now name `palisade-sec connect llm`.** Only the
  new Anthropic branch mentioned it; the default (`typesafe`) and the
  OpenAI-compatible branch still told you to edit a `.env`, so a
  first-time `audit` pointed away from the command 0.6.0 adds.

### Unchanged on purpose

The offline core (`scan`, `map`, `baseline`, `fix`) uses none of this: no
key, no network, no telemetry. A test asserts the scanner does not even
import the connected code or any HTTP machinery, and it fails under
mutation. The connected commands use only stdlib HTTP, so the base install
gains no dependency.

## 0.5.2 - 2026-09-22

Standards, supply chain and distribution, plus an honest recall number.

### Added

- **CWE and OWASP LLM Top 10 2025 mapping on every finding.** Each rule maps
  to CWE-1427 (Improper Neutralization of Input Used for LLM Prompting), to
  CWE-1426 (Improper Validation of Generative AI Output) where model output
  reaches a sink, plus the sink's classic CWE (94, 78, 89, 918; 441 for agent
  handoffs), and to OWASP LLM01:2025 plus LLM05:2025 (LLM06:2025 for
  handoffs). JSON findings gain `cwe` and `owasp_llm`; the terminal and
  markdown reports gain a "Maps:" line; references point at the OWASP 2025
  category pages. Names and URLs verified against genai.owasp.org and
  cwe.mitre.org (CWE 4.20). Custom rules may declare `cwe`, `owasp_llm` and
  `security_severity`; all optional and validated.
- **SARIF for GitHub code scanning:** CWE tags (`external/cwe/cwe-094`),
  OWASP tags (`external/owasp-llm/llm01-2025`) and `security-severity`
  (exec/shell 9.3 critical, SQL 8.8, handoff 8.1, HTTP 5.3 medium), so alerts
  rank and filter properly in the Security tab.
- **GitHub Action** (`uses: arpankernel/palisade@v0.5.2`): scans the repo
  (JS/TS included), uploads SARIF to the Security tab, and fails the job on a
  new HIGH finding. Inputs are passed through env vars and validated, never
  interpolated into the script. Self-tested in CI on every PR.
- **pre-commit hook** (`id: palisade-sec`).

### Supply chain

- Every GitHub Action in every workflow is pinned to a full commit SHA (tag
  kept in a comment), including the PyPI publish step; Dependabot keeps the
  pins current.
- Releases attach a CycloneDX SBOM and a Sigstore-signed build-provenance
  attestation (`gh attestation verify <file> --repo arpankernel/palisade`).
  PyPI already stores PEP 740 attestations via Trusted Publishing.

### Fixed

- **The benchmark corpus is actually pinned.** `corpus/fetch.py` wrote
  `repos.lock.json` but never read it, so every run re-cloned the latest
  default branch of the 23 clean repos. It now checks out exactly the locked
  commits (`--update` moves them deliberately), and a failed fetch fails the
  run instead of scoring a partial corpus.

### Measurement

- **Recall is now measured on 10 hand-verified paths instead of 3: 0.200**
  (tp=2, fn=8; precision still 1.000, 0 false positives). An audit of the
  clean repos found 7 real paths Palisade misses (3 direct: raw SQL in
  crewai-tools and griptape, the Anthropic SDK's bash tool; 4 sandboxed by
  default in autogen and dspy). Each is labelled with its exact sink code,
  and the label test now checks that code at the pinned commit. The misses
  point at three engine gaps, now the top of the Phase 2 roadmap.
- The precision harness guard also fails a labelled repo that mints no
  untrusted sources.

## 0.5.1 - 2026-09-22

A pre-launch hardening release. Three independent audits (fresh-install
behaviour, the tool's own security, and every public claim) ran against the
published 0.5.0. Everything they reproduced is fixed here, each with a
regression test that fails on 0.5.0. Re-validated on the pinned 26-repo
benchmark: precision **1.000** (0 false positives), recall 0.667 unchanged,
and no new finding of any severity in the 23 clean repos.

### Security

- **Output writes no longer follow planted symlinks.** A repository that
  shipped `palisade-report.md`, `palisade-fixes.md`, `palisade-review.md` or a
  `.palisade` directory as symlinks made `scan --report`, `fix`, `review
  --report` and `baseline` overwrite files outside it (e.g. `~/.bashrc`) when
  run inside an untrusted clone. Writes now refuse a symlink at the file or
  any directory below the working directory, and open with `O_NOFOLLOW`.
- **Scanned text is shown, never interpreted.** Control characters (terminal
  escape sequences) and Unicode bidi overrides ("Trojan Source") in snippets
  and file paths are neutralized into visible escapes, so scanned code can no
  longer rewrite Palisade's own terminal output. Backticks and pipes in paths
  and snippets can no longer break out of markdown report formatting.
- **A cloned repo's `.env` cannot redirect your key.** An endpoint chosen by a
  `.env` file is used only with a key from that same file.
- **A repo's own config cannot point `rules_dir` outside the repo.** `--rules`
  is unrestricted.

### Fixed

- **Only allowlist-shaped sanitizers silence a finding.** 0.5.0 silenced
  PI-EXEC when the sanitizer was a denylist search of the input (`if "import"
  in code: raise`), a length check, or any raise (e.g. `ast.parse` in a
  try/except), contradicting "downgrade, never silence". Those now land as
  MED "unverified sanitizer". Silencing requires an allowlist lookup, an AST
  node-type allowlist, an enum-literal guard, or a strict matcher such as
  `re.fullmatch` (now also recognized inside an `if` condition).
- **`review`, `audit` and `redteam --execute` no longer crash on a plain
  install.** Without the `[judge]` extra they printed an httpx
  `ModuleNotFoundError` traceback. `review` now runs taint-only and says why;
  `audit` and `redteam --execute` exit 2 with an install hint.
- **An empty scan is never a pass.** Scanning zero files (a JS/TS repo
  without `[js]`, an over-broad ignore, an empty target) printed a green tick
  and passed `--ci`. It now warns in every output, and `scan`/`review`/
  `audit --ci` exit 2. SARIF records the run as unsuccessful.
- **A copy-pasted known vulnerability is a new finding.** Baseline
  fingerprints are line-independent, so a duplicate passed `--ci`; the diff
  now compares occurrence counts.
- **`redteam --execute`: an unreachable target is not "0 landed".** Attacks
  with no response are reported as errors, are never scored or sent to the
  judge, and fail `--ci`.
- **`.env` is read from the working directory.** 0.5.0 searched from the
  installed package, so the documented `.env` setup never worked for pip/uvx.
- **gitignore negations (`!src/`) are honoured.** An allowlist-style
  `.gitignore` previously hid the whole source tree.
- **Only the real TypeSafe endpoint counts as verified.** Pointing the
  TypeSafe adapter elsewhere now gets the unverified-backend posture cap.
- **Rule references are accurate.** PI-EXEC no longer cites Langflow's
  CVE-2025-3248 (no LLM on its path; the corpus scores it out of contract),
  and PI-SQL no longer cites Vanna's CVE-2024-5565/-5826 (exec bugs). A test
  fails if a rule cites a CVE the corpus scores clean.

### Changed

- **Exit code 3 means an internal error** (a bug, not a finding). 0.5.0 exited
  1 on a crash, the same as "found a HIGH". `PALISADE_DEBUG=1` shows the
  traceback.
- Exit code 2 now also covers: a `--ci` run that scanned nothing, a missing
  `[judge]` extra or key, an explicitly named `--config`/`--rules` that does
  not exist, a refused output path, and red-team attacks that got no response
  under `--ci`.
- A judge outage during `review` falls back to taint-only; it never fails the
  deterministic `--ci` gate. During `audit` it is a clean exit 2.
- Every command reports warnings, skipped files and notes (on stderr, so
  `--json` stays parseable). JS/TS files skipped for want of `[js]` are a
  warning, and files that failed to parse are counted beside the verdict.
- `redteam --variants` is range-checked against the templates that exist
  (1-2); larger values silently produced duplicates.
- The precision harness prints the number of files it scanned.
- `.env.example` no longer sets the endpoint and model (both have defaults).

### Internal

- New CI job **"Plain install (no extras)"**: builds the wheel and drives every
  command from a fresh venv with no extras (`scripts/smoke_install.sh`). It
  also runs in the release workflow before publishing. It fails on the 0.5.0
  wheel and passes on 0.5.1.

## 0.5.0 - 2026-09-21

The applied agentic-safety layer. The deterministic core (`scan`, `map`,
`baseline`, `fix`) stays offline and keyless. A new judgment layer is
bring-your-own-endpoint: it reads an endpoint and key from `.env` and is used
only by `audit` and `review`. Before release, an adversarial self-audit hardened
the engine: it found and fixed a critical sanitizer-silencing bug, two taint
false negatives, false-positive vectors in the multi-agent analysis, a vacuous
calibration metric, and a SARIF path bug - each with a permanent regression test.
Re-validated on the pinned 26-repo benchmark: precision **1.000**, 0 false
positives, the Vanna CVE still caught.

### Added

- **SARIF output + code-scanning Action.** `scan --sarif` emits SARIF 2.1.0
  (severity high->error/med->warning/low->note; sink as the primary location,
  source and LLM boundary as related locations; line-shift-resilient
  fingerprints). A five-line GitHub Action (`.github/workflows/code-scanning.yml`,
  which also dogfoods on Palisade's own `src`) puts findings in the Security tab.
  This is the Phase-1 distribution wedge - findings where AppSec pipelines already
  look, in a copy-paste workflow.
- **Multi-agent graph (`map`).** `map` now extracts the agent topology: nodes are
  agents (with the tools they hold and the capabilities those tools exercise),
  edges are handoffs (`handoffs=[...]`). It shows which entry agents can reach a
  dangerous capability across a handoff, and adds an `agent_graph` block to
  `--json`. Deterministic and offline. Framework adapters: the explicit-kwarg
  (OpenAI Agents SDK-style `Agent(tools=, handoffs=)`), **LangGraph**
  (`add_node`/`add_edge`, a node's capabilities read from its function body), and
  **CrewAI** (`Crew(agents=, process=)` - sequential chains the agents,
  hierarchical connects the first to the rest).
- **Judgment-layer calibration harness (`scripts/calibrate.py`).** Measures how
  well a JudgeBackend agrees with ground truth on a labelled corpus
  (`corpus/judgment/cases.yaml`): per-question precision / recall / accuracy plus
  a Brier score for the yes/no signals, and exact-tier accuracy + MAE for the
  severity/harm scores. Exits non-zero below the corpus thresholds, so judged
  quality can only ratchet up. This is what turns the exploitability / agency /
  posture signals from "uncalibrated" into measured; the scoring is pure and
  tested offline, and a real keyed run publishes the numbers.
- **Multi-agent calibration.** Labeled fixtures under `corpus/fixtures/agents/`
  (must-flag handoff paths + must-stay-silent safe wirings) join the precision
  corpus, so `PI-AGENT-HANDOFF` is measured (precision/recall) and gated in CI -
  and now in the test suite too (`test_precision_gate.py`). Fixed a real bug the
  fixtures caught: the analysis merged same-named agents across files; it now
  scopes agents per module so findings are attributed to the right file.
- **Red-team execution (`redteam --execute`).** The advisory synthesis can now
  be fired at a live target you own, gated by `--approve` plus a `--target` URL
  (or `PALISADE_REDTEAM_TARGET`). `HttpTarget` POSTs each attack and reads the
  output/tool-calls across common response shapes; a judge-backed scorer decides
  whether each attack landed (deterministic tool-invocation checks plus a
  JudgeBackend for behavioral judgment). `--execute --ci` exits non-zero if any
  attack lands. Palisade never executes your code; it drives the endpoint you
  provide, in your environment. Synthesis stays offline and dependency-free.
- **`PI-AGENT-HANDOFF` finding (`scan`).** A multi-agent prompt-injection path:
  untrusted input runs an agent that can hand off (>=1 hop) to an agent holding a
  dangerous-capability tool. Deterministic, offline, and precision-first - it
  fires only on a complete untrusted -> run -> handoff -> dangerous path, so a
  constant input, a handoff to only-safe agents, or a standalone dangerous agent
  stays silent. Flows through `--json`, `--ci`, and the baseline like any finding.
  v1 tracks untrustedness intra-procedurally (source at the run site or a
  variable assigned from one in the same function).
- **Judgment backends (`palisade_sec.judge`).** One `JudgeBackend` interface
  with two adapters, selected in `.env`: **TypeSafe** (default, calibrated
  typed answers, `verified=True`) and a **generic OpenAI-compatible** endpoint
  (strict-JSON prompt validated against a schema, labelled best-effort and
  `verified=False`). Batched: one call per artifact. Keys are read from the
  environment only and never logged. See `.env.example`.
- **`[judge]` extra** (`httpx`, `python-dotenv`); `[semantic]` kept as an alias.
- **Taint-path exploitability check.** Grounded in a verified `source -> LLM ->
  sink` dataflow, it asks the backend to judge exploitability and impact of that
  specific path. Uncalibrated until scored on the corpus. A verified backend
  refines a finding up or down; an unverified backend is advisory only and never
  moves the deterministic risk.
- **`palisade-sec review`.** One prioritized report composing scan + map + the
  semantic checks + red-team synthesis, with a **posture score** (0-100 plus a
  named band: Critical / High / Moderate / Low). The score is derived from the
  tier counts and printed with the breakdown beside it; it is a posture over
  *detected* findings (`likelihood x impact`), not a safety score. When the
  judgment layer ran, the report says so and marks it uncalibrated; an unverified
  backend cannot manufacture a Critical posture. Terminal, `--json`, `--report`
  (markdown). `--ci` gates only on new HIGH taint findings (baseline-diffed);
  judged signals never gate.
- **`audit` now runs both checks** (excessive agency over tools, exploitability
  over taint paths), so it produces findings on apps that expose no agent tools.
- **`review` judges once per run.** It performs a single judgment pass and emits
  both the composed posture and the audit view (`audit_findings` in `--json`)
  from it, so `audit` and `review` never disagree within a run and a run makes
  half the endpoint calls. Judged output is deterministic within a run but not
  across runs, because the model is probabilistic; the posture score is not
  claimed to be stable run-to-run.

### Changed

- `audit` now reads its backend from `.env` (`PALISADE_JUDGE_BACKEND`,
  `PALISADE_JUDGE_ENDPOINT`, `PALISADE_JUDGE_MODEL`, key vars) instead of the
  TypeSafe SDK, so any OpenAI-compatible endpoint works. An unverified backend
  can never emit a BLOCK on judgment alone; such a decision downgrades to
  REVIEW. The judgment layer is uncalibrated until scored on the corpus.

### Fixed

- **Sanitizer silencing bypass (critical).** A sanitizer body that only
  transformed its input and returned it (`code = code.replace(...); return
  code` - the Vanna CVE-2024-5565 shape) was treated as verified and fully
  suppressed the finding, because any `raise`, terminating guard, or `re.match`
  counted as validation. A transform-and-return body is now cosmetic unless it
  carries a strong signal (a membership test or `re.fullmatch` family call);
  `re.match` was dropped from the validator set. This restores the documented
  "downgrade, never silence" contract.
- **Empty SQL parameters no longer disarm the sink.** `cursor.execute(sql, ())`
  (or `[]`, `{}`, `params={}`) binds nothing, so the tainted SQL string is what
  executes; it is no longer treated as parameterized. A real, non-empty binding
  still suppresses.
- **`try`/`except` no longer erases taint.** `try: code = <llm output> except:
  code = "safe"` followed by `exec(code)` dropped the finding, because handler
  state overwrote the try-body state. The two branches are now joined.
- **`PI-AGENT-HANDOFF` taint is cast/sanitizer aware and flow-sensitive.** The
  multi-agent finding (which gates `scan --ci`) no longer treats `run(agent,
  int(x))` or `run(agent, sanitize(x))` as untrusted, and an unconditional clean
  reassignment now clears taint - closing false-positive vectors that could break
  a user's build.
- **Calibration no longer reports a vacuous precision.** A signal with no
  positive predictions (or no positive labels) reported precision `1.000` and
  cleared the gate. Precision and recall are now undefined (null) when their
  denominator is zero; the gate requires a signal to be exercised, and an
  unexercised signal is reported rather than silently passing.
- **SARIF URIs are relative to the repository root.** Finding paths are relative
  to the scan target, so a subdirectory scan (`scan src`) mislocated every GitHub
  code-scanning alert. `to_sarif` now takes a base and the CLI prepends the scan
  base relative to the working directory.

### Performance

- **`resolve()` is no longer O(n^2) on large TypeScript repos.** The dotted-suffix
  fallback scanned the whole function registry per call site; it now consults a
  last-segment index. gemini-cli `packages/core/src` (465 files) went from not
  finishing in 90s to 13.9s, with byte-identical findings.

## 0.4.0 - 2026-09-16

Phase 0 of the roadmap is complete: quality is now measured against a pinned
benchmark corpus instead of asserted. Precision **1.000**, recall **0.667**,
F1 **0.800** across 26 third-party repos and 17,343 scanned files, with zero
false positives. The single miss (PandasAI CVE-2024-12366, whose exec sits
behind dynamically dispatched pipeline steps) is labelled as a miss on
purpose, so recall stays honest and the gap stays visible.

### Added

- **Inline suppressions.** `# palisade: ignore[PI-EXEC] - reason`, on the
  sink line or the one above, with `#` and `//` so Python and JS/TS share
  one syntax. Deliberately loud: suppressed findings are counted, carry
  their reason into `--json` under `suppressions`, and a comment that stops
  matching anything is reported as stale. Without this, a single unfixable
  finding disables the whole scanner.
- **Benchmark corpus.** `corpus/repos.yaml` pins 26 repos with resolved
  SHAs, fetched by `corpus/fetch.py`; `scripts/precision.py` scores both it
  and the fast fixture corpus. A weekly workflow runs the slow one.
- **False-positive regression harness.** `tests/fixtures/regressions/` with
  auto-discovery, so any reported false positive becomes a permanent
  must-stay-silent test and precision only ratchets upward.
- **Releases via Trusted Publishing.** Tag-triggered OIDC publishing with no
  API token anywhere, gated on the full test suite, a tag/version match
  check, an sdist contents check, and a smoke test of the built wheel.

### Changed

- **Findings are deduplicated by sink.** One dangerous line is one thing to
  fix, so it is reported once even when several rules match it or several
  untrusted sources converge on it. The best-evidenced trace is kept and
  collapsed duplicates are recorded in `count`. Previously a library entry
  point with both an `input()` path and a public-parameter path reaching the
  same `exec` produced two identical findings.
- The precision harness scores recall at any severity, since a real
  vulnerability that Palisade deliberately downgrades to MED is still found,
  and scores precision on HIGH only, since advisory rules never gate CI.

### Fixed

- Scanning a file with an invalid escape sequence printed the whole source
  line to stderr, because `ast.parse` raises `SyntaxWarning` and Python
  echoes the offending line. On one real repo that dumped 40 KB of file
  contents and bypassed the 200-char snippet redaction.
- The precision gate reported success on an unlabelled corpus, because
  precision is defined as 1.0 when tp+fp is 0. It now fails when it measures
  nothing.

## 0.3.4 - 2026-09-16

- Packaging fix: the source distribution no longer bundles the documentation
  site. The 0.3.3 sdist accidentally swept in docs-site/node_modules, which
  made it 85 MB across 8,599 files, because hatchling does not honour nested
  .gitignore files. Wheels were never affected, so normal installs were fine.
  The sdist now excludes docs-site, website and .github, and is back to
  roughly 163 KB.


## 0.3.3 - 2026-09-16

- Removed every em dash from the README, docs, website, rule text and code
  comments in favour of plain hyphens, for a cleaner reading tone. This
  release exists so the PyPI project description picks the change up, since
  descriptions are immutable per release.
- Softened the website palette from a vivid crimson (#A31621) to a calmer
  maroon (#6E1F2A). The large fills (page frame, terminal panels, final CTA)
  were harsh to read against the cream canvas.


## 0.3.2 - 2026-09-16

- PyPI listing health: absolute URLs for the README demo image and the
  rules-guide link (relative paths render broken on the PyPI project
  page); package summary now says Python **and JavaScript/TypeScript**.

## 0.3.1 - 2026-09-16

- Terminal output: escape rich markup in notes/warnings/skips so literal
  brackets render verbatim (the `pip install 'palisade-sec[js]'` hint was
  losing its `[js]`). Found by the full-stack verification pass.

## 0.3.0 - 2026-09-16

The "everything deferred" release: multi-language, framework-aware, and
able to propose fixes.

- **JavaScript/TypeScript frontend** (tree-sitter, optional `[js]` extra):
  `.js`/`.mjs`/`.cjs`/`.jsx`/`.ts`/`.tsx` lower into the same taint IR with
  **zero engine changes** - the multi-language architecture, proven. Express
  sources (`req.body`, `req.query`), `eval`/`new Function`/`vm.runIn*`,
  `child_process.exec[Sync]`, `pool.query` sinks; `.includes()` enum guards;
  `this` maps to `self` so class-field tracking works. 1,576 mixed
  Python+TS files (Langflow) scan in ~36s with zero crashes and zero FPs.
- **FastAPI / decorator sources**: rules can declare `kind: decorator`
  sources (`*.post`, `*.route`, ...) - route-handler parameters (including
  pydantic bodies) become untrusted automatically.
- **Class-hierarchy method resolution**: `self.m()` resolves through base
  classes and, when exactly one concrete implementation exists, through
  subclasses (abstract-hook/single-provider pattern). Ambiguous
  many-provider dispatch stays unresolved - precision first.
- **New seeded rules**: `PI-HTTP` (LLM-chosen URL fetched - SSRF/exfil,
  advisory MED) and `PI-FRAMEWORK-EXEC` (framework LLM wrappers:
  `submit_prompt`, `call_llm`, `generate_code`, ... → execution step).
  With library mode, builtin rules now flag the real Vanna CVE-2024-5565
  with no custom rule at all.
- **`palisade-sec fix`**: deterministic, offline remediation plans - a
  rule-tailored guardrail plus a regression pytest per finding, written to
  `palisade-fixes.md`. Never modifies scanned code, never calls an LLM.
- **Sanitizer verification refinements**: raises anywhere in the body
  (including except handlers) count as validation, `re.fullmatch`-style
  validator calls count, and verification follows one level of delegation.
- **Engine precision**: cross-rule dedup (one source→sink vulnerability is
  one finding; most specific rule wins); sink-named calls that resolve to
  real project functions are followed instead of flagged at the boundary;
  sources match on dotted prefixes (`req.body.q`).
- Demo: `docs/demo.svg` regenerable via `scripts/make_demo.py`.

## 0.2.0 - 2026-09-16

Driven by the proof scans against real CVE repos (docs/proof-scans.md).

- **Library mode**: `palisade-sec scan --assume-params-untrusted` (or
  `assume_params_untrusted = true` in config) treats parameters of public
  functions as untrusted sources (`param:<name>` in traces). Off by default.
- **Sanitizer strictness**: sanitizer name-matches now suppress only when
  trusted (known frameworks, `trusted: true` in rules) or when the resolved
  project-local function body shows a real allowlist/validation shape.
  A sanitizer in name only downgrades the finding to MED
  **"unverified sanitizer"** instead of silencing it - Vanna's cosmetic
  `_sanitize_plotly_code` (CVE-2024-5565) is the canonical case.
- JSON schema: `partial_defenses[].kind` added
  (`partial_defense` | `unverified_sanitizer`).
- **Engine**: abstract stub bodies (`pass` / `...` / docstring-only / bare
  raise) propagate taint like unknown calls instead of dropping it; mutating
  collection methods (`x.append(tainted)`) taint the collection; sink specs
  can declare which positional arguments are dangerous (`taint_args: [0]`
  for exec/eval - a tainted environment dict is not code execution).
- Rescanning the real vanna v0.5.5 with library mode + a one-line
  `*.submit_prompt` wrapper rule now flags exactly the CVE-2024-5565 sink
  (base.py:1998) and nothing else; an offline fixture pins this
  (tests/test_vanna_regression.py).

## 0.1.0 - 2026-09-16

Initial release: Python frontend (stdlib ast) → language-agnostic taint IR →
engine; PI-EXEC / PI-SHELL / PI-SQL rules; sanitizer resolution and
partial-defense downgrade; bounded inter-procedural propagation; `scan` and
`baseline` CLI with line-shift-resilient fingerprints; vulnerable example
app as acceptance fixtures.
