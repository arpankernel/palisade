"""Acceptance tests against examples/vulnerable-app.

The "safe cases stay silent" assertions are the highest-value tests in the
repo: a false positive is worse than a miss.
"""

from conftest import EXAMPLE_APP, find_line, func_range

APP = EXAMPLE_APP / "app.py"
EXECUTOR = EXAMPLE_APP / "executor.py"


def _sinks(scan, rule=None, severity=None):
    out = []
    for f in scan.findings:
        if rule and f.rule_id != rule:
            continue
        if severity and f.severity != severity:
            continue
        out.append((f.sink.file, f.sink.line))
    return out


# ---------------------------------------------------------------------------
# must-flag: the exploitable cases are HIGH
# ---------------------------------------------------------------------------


def test_exec_vuln_flagged_high(example_scan):
    line = find_line(APP, "exec(code)", after="def calc(")
    assert ("app.py", line) in _sinks(example_scan, rule="PI-EXEC", severity="high")


def test_sql_vuln_flagged_high(example_scan):
    line = find_line(APP, "cur.execute(sql)", after="def ask_db(")
    assert ("app.py", line) in _sinks(example_scan, rule="PI-SQL", severity="high")


def test_shell_vuln_flagged_high(example_scan):
    line = find_line(APP, "subprocess.run(command, shell=True)", after="def ops(")
    assert ("app.py", line) in _sinks(example_scan, rule="PI-SHELL", severity="high")


def test_multi_hop_vuln_flagged(example_scan):
    """Source in app.py, LLM in llm_utils.py, sink in executor.py."""
    line = find_line(EXECUTOR, "exec(code)")
    hits = [
        f
        for f in example_scan.findings
        if f.rule_id == "PI-EXEC" and (f.sink.file, f.sink.line) == ("executor.py", line)
    ]
    assert hits, "multi-hop source->LLM->sink path across files was not flagged"
    f = hits[0]
    assert f.severity == "high"
    assert f.source.file == "app.py"  # trace points back to the real source
    assert f.llm.file == "llm_utils.py"


# ---------------------------------------------------------------------------
# partial defense: MED "risky", not HIGH and not silent
# ---------------------------------------------------------------------------


def test_partial_defense_flagged_med_risky(example_scan):
    line = find_line(APP, "exec(code)", after="def calc_guarded(")
    hits = [f for f in example_scan.findings if (f.sink.file, f.sink.line) == ("app.py", line)]
    assert hits, "partial-defense case must not be silent"
    f = hits[0]
    assert f.severity == "med"
    assert f.risky
    assert f.partial_defenses, "the denylist gate must be reported on the finding"


# ---------------------------------------------------------------------------
# must-NOT-flag: the safe cases stay silent (highest-value tests)
# ---------------------------------------------------------------------------


def _assert_silent(example_scan, func_name):
    start, end = func_range(APP, func_name)
    offenders = [
        f for f in example_scan.findings if f.sink.file == "app.py" and start <= f.sink.line <= end
    ]
    assert not offenders, f"FALSE POSITIVE in safe case {func_name}: " + "; ".join(
        f"{f.rule_id}@{f.sink.line}" for f in offenders
    )


def test_safe_sanitizer_silent(example_scan):
    _assert_silent(example_scan, "calc_safe")


def test_safe_subprocess_arg_list_silent(example_scan):
    _assert_silent(example_scan, "ping")


def test_safe_parameterized_sql_silent(example_scan):
    _assert_silent(example_scan, "lookup")


def test_safe_constant_prompt_silent(example_scan):
    _assert_silent(example_scan, "nightly_report")


def test_safe_logged_output_silent(example_scan):
    _assert_silent(example_scan, "chat")


def test_safe_enum_constrained_silent(example_scan):
    _assert_silent(example_scan, "action")


# ---------------------------------------------------------------------------
# exactness: nothing beyond the five known findings
# ---------------------------------------------------------------------------


def test_exact_finding_count(example_scan):
    assert len(example_scan.findings) == 5, [
        (f.rule_id, f.severity, f.sink.file, f.sink.line) for f in example_scan.findings
    ]


def test_no_files_skipped(example_scan):
    assert example_scan.skipped == []
    assert example_scan.files_scanned >= 6
