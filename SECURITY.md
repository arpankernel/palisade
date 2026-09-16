# Security Policy

Palisade is a security tool, so it is held to a higher bar than the code it
scans. If you believe you've found a vulnerability in Palisade itself, thank
you - please report it privately.

## Reporting a vulnerability

- **Preferred:** GitHub private vulnerability reporting -
  https://github.com/arpankernel/palisade/security/advisories/new
- Please do **not** open a public issue for suspected vulnerabilities.

Include: the version (`palisade-sec --version`), a minimal reproducer
(ideally a hostile input file), and the impact you believe it has.

**Response targets:** acknowledgement within 72 hours; assessment and a fix
or mitigation plan within 14 days for confirmed issues. Credit is given in
the changelog unless you prefer otherwise.

## What counts as a vulnerability here

The scanner's own safety contract - violations of any of these are
security bugs, not ordinary bugs:

1. **SF-1 - code execution:** the scanner executing, importing, `exec`ing,
   or `eval`ing any code or config from a scanned target, ever. (Pure
   parsing only; enforced by audit-hook tests over a hostile corpus.)
2. **SF-2 - network:** `scan`/`baseline`/`fix` making any network call.
3. **SF-3 - filesystem escape:** reading outside the scan target (e.g. via
   symlinks) or writing anywhere except `.palisade/` and explicitly
   requested output files.
4. **Denial of service:** any input file that crashes the scanner, hangs it
   past its budgets, or exhausts memory instead of being skipped with a
   warning.
5. **Data leakage:** reports/logs carrying materially more source content
   than the finding traces are designed to include (single lines, capped at
   200 chars).

False negatives/positives in *detection* are quality issues - please file
those as regular GitHub issues with a fixture.

## Supported versions

The latest minor release line receives security fixes. Older versions:
please upgrade - `pip install -U palisade-sec`.

## Our own supply chain

Runtime dependencies are deliberately few (typer, rich, pydantic, pyyaml;
tree-sitter only via the optional `[js]` extra), pinned via a committed
`uv.lock`, and releases are built and published from CI-verified commits.
Signed releases + SBOM/provenance are on the roadmap (Phase 4 - Certify).
