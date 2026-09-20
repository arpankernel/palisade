"""PI-AGENT-HANDOFF (Phase 1b). Precision-first: a finding needs a complete
untrusted -> run -> handoff -> dangerous-agent path. Every must-flag case has a
must-stay-silent twin."""

from __future__ import annotations

from pathlib import Path

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.agents.findings import find_agent_handoff_findings

TOOLS = (
    "import shutil\n"
    "from flask import request\n"
    "from agents import Agent, Runner, function_tool\n"
    "@function_tool\n"
    "def delete_files(path):\n    shutil.rmtree(path)\n"
    "@function_tool\n"
    "def greet(name):\n    return f'hi {name}'\n"
)


def _findings(src: str):
    mod = PythonFrontend().lower_file("app.py", "app.py", src)
    assert not isinstance(mod, ParseFailure)
    return find_agent_handoff_findings([mod])


# -- must flag ---------------------------------------------------------------


def test_untrusted_handoff_to_dangerous_agent_is_flagged():
    src = TOOLS + (
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[ops])\n"
        "def handle():\n"
        "    q = request.json['task']\n"
        "    return Runner.run(triage, q)\n"
    )
    fs = _findings(src)
    assert len(fs) == 1
    f = fs[0]
    assert f.rule_id == "PI-AGENT-HANDOFF"
    assert f.severity == "high"
    assert "ops" in f.sink.snippet
    assert "file_write" in f.sink.detail


def test_receiver_form_run_is_flagged():
    src = TOOLS + (
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[ops])\n"
        "def handle():\n"
        "    return triage.run(request.json['q'])\n"
    )
    assert len(_findings(src)) == 1


def test_two_hop_handoff_is_flagged_with_lower_confidence():
    src = TOOLS + (
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "mid = Agent(name='mid', tools=[], handoffs=[ops])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[mid])\n"
        "def handle():\n"
        "    return Runner.run(triage, request.json['q'])\n"
    )
    fs = _findings(src)
    assert len(fs) == 1
    assert fs[0].confidence == "MEDIUM"  # two handoffs deep


# -- must stay silent (the twins) -------------------------------------------


def test_constant_input_is_silent():
    src = TOOLS + (
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[ops])\n"
        "def handle():\n"
        "    return Runner.run(triage, 'run the nightly summary')\n"
    )
    assert _findings(src) == []


def test_handoff_to_only_safe_agents_is_silent():
    src = TOOLS + (
        "helper = Agent(name='helper', tools=[greet])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[helper])\n"
        "def handle():\n"
        "    return Runner.run(triage, request.json['q'])\n"
    )
    assert _findings(src) == []


def test_standalone_dangerous_agent_run_is_silent():
    # Untrusted input straight into a dangerous agent with NO handoff is not a
    # multi-agent finding (that is single-agent excessive-agency territory).
    src = TOOLS + (
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "def handle():\n"
        "    return Runner.run(ops, request.json['q'])\n"
    )
    assert _findings(src) == []


def test_no_run_site_is_silent():
    src = TOOLS + (
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[ops])\n"
    )
    assert _findings(src) == []


# -- end to end through run_scan --------------------------------------------


def _write(tmp: Path, body: str) -> Path:
    d = tmp / "agentapp"
    d.mkdir()
    (d / "app.py").write_text(TOOLS + body, encoding="utf-8")
    return d


def test_run_scan_surfaces_agent_handoff(tmp_path):
    from palisade_sec.scanner import run_scan

    d = _write(
        tmp_path,
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[ops])\n"
        "def handle():\n"
        "    return Runner.run(triage, request.json['q'])\n",
    )
    findings = run_scan(d).findings
    assert any(f.rule_id == "PI-AGENT-HANDOFF" for f in findings)


def test_cross_file_agents_are_not_merged():
    # Two files each define `ops`/`triage`; agents are module-local, so only the
    # file with an untrusted run must flag, attributed to that file (regression:
    # a cross-module graph used to merge same-named agents and misattribute).
    common = (
        "ops = Agent(name='ops', tools=[delete_files])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[ops])\n"
    )
    vuln = TOOLS + common + "def handle():\n    return Runner.run(triage, request.json['q'])\n"
    safe = TOOLS + common + "def handle():\n    return Runner.run(triage, 'constant task')\n"
    m1 = PythonFrontend().lower_file("vuln.py", "vuln.py", vuln)
    m2 = PythonFrontend().lower_file("safe.py", "safe.py", safe)
    assert not isinstance(m1, ParseFailure) and not isinstance(m2, ParseFailure)
    fs = find_agent_handoff_findings([m1, m2])
    assert len(fs) == 1
    assert fs[0].sink.file == "vuln.py"


def test_run_scan_safe_twin_is_clean(tmp_path):
    from palisade_sec.scanner import run_scan

    d = _write(
        tmp_path,
        "helper = Agent(name='helper', tools=[greet])\n"
        "triage = Agent(name='triage', tools=[], handoffs=[helper])\n"
        "def handle():\n"
        "    return Runner.run(triage, request.json['q'])\n",
    )
    assert not any(f.rule_id == "PI-AGENT-HANDOFF" for f in run_scan(d).findings)
