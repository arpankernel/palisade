from __future__ import annotations

from pathlib import Path

import pytest

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


# -- container entry points: crew.kickoff() / compiled-graph .invoke() /
# add_conditional_edges, exercised end to end through run_scan. Each case is
# (label, source, expect_finding); the vulnerable and safe variant of each
# entry-point mechanism live side by side so a regression in either direction
# - a real path going silent, or a safe wiring starting to flag - fails here.
_CREW_TOOLS = (
    "import subprocess\n"
    "from crewai import Agent, Crew\n"
    "from crewai.tools import tool\n"
    "@tool\n"
    "def shell(cmd):\n    subprocess.run(cmd, shell=True)\n"
    "@tool\n"
    "def greet(name):\n    return f'hi {name}'\n"
)
_LANGGRAPH_TOOLS = (
    "import shutil\n"
    "from langgraph.graph import StateGraph, START\n"
    "def triage(state):\n    return state\n"
    "def escalate(state):\n    shutil.rmtree(state['path'])\n"
)

CONTAINER_ENTRY_CASES = [
    pytest.param(
        _CREW_TOOLS + "researcher = Agent(role='researcher', tools=[])\n"
        "executor = Agent(role='executor', tools=[shell])\n"
        "crew = Crew(agents=[researcher, executor])\n"
        "def handle():\n"
        "    return crew.kickoff(inputs={'topic': request.json['topic']})\n",
        True,
        id="crew-kickoff-vulnerable",
    ),
    pytest.param(
        _CREW_TOOLS + "researcher = Agent(role='researcher', tools=[])\n"
        "helper = Agent(role='helper', tools=[greet])\n"
        "crew = Crew(agents=[researcher, helper])\n"
        "def handle():\n"
        "    return crew.kickoff(inputs={'topic': request.json['topic']})\n",
        False,
        id="crew-kickoff-safe-target",
    ),
    pytest.param(
        _CREW_TOOLS + "researcher = Agent(role='researcher', tools=[])\n"
        "executor = Agent(role='executor', tools=[shell])\n"
        "crew = Crew(agents=[researcher, executor])\n"
        "def handle():\n"
        "    return crew.kickoff(inputs={'topic': 'quarterly report'})\n",
        False,
        id="crew-kickoff-constant-input",
    ),
    pytest.param(
        _LANGGRAPH_TOOLS + "g = StateGraph(dict)\n"
        "g.add_node('triage', triage)\n"
        "g.add_node('escalate', escalate)\n"
        "g.add_edge(START, 'triage')\n"
        "g.add_edge('triage', 'escalate')\n"
        "app = g.compile()\n"
        "def handle():\n"
        "    return app.invoke({'path': request.json['q']})\n",
        True,
        id="compiled-graph-invoke-vulnerable",
    ),
    pytest.param(
        _LANGGRAPH_TOOLS + "g = StateGraph(dict)\n"
        "g.add_node('triage', triage)\n"
        "g.add_node('escalate', escalate)\n"
        "g.add_edge(START, 'triage')\n"
        "g.add_edge('triage', 'escalate')\n"
        "app = g.compile()\n"
        "def handle():\n"
        "    return app.invoke({'path': '/tmp/fixed'})\n",
        False,
        id="compiled-graph-invoke-constant-input",
    ),
    pytest.param(
        _LANGGRAPH_TOOLS + "def route(state):\n"
        "    return 'escalate' if state.get('risky') else '__end__'\n"
        "g = StateGraph(dict)\n"
        "g.add_node('triage', triage)\n"
        "g.add_node('escalate', escalate)\n"
        "g.add_edge(START, 'triage')\n"
        "g.add_conditional_edges('triage', route, "
        "{'escalate': 'escalate', '__end__': '__end__'})\n"
        "app = g.compile()\n"
        "def handle():\n"
        "    return app.invoke({'path': request.json['q']})\n",
        True,
        id="conditional-edges-vulnerable",
    ),
]


@pytest.mark.parametrize("source, expect_finding", CONTAINER_ENTRY_CASES)
def test_container_entry_points_end_to_end(tmp_path, source, expect_finding):
    """A run site reached only through a container (crew.kickoff(),
    a compiled LangGraph's .invoke()) or only through add_conditional_edges
    (not a plain add_edge) must flag exactly like a direct agent.run() call
    - and stay silent under the same conditions (safe target, constant
    input) a direct call would. Runs the real scan pipeline, matching what
    `palisade-sec scan` reports to a user."""
    from palisade_sec.scanner import run_scan

    d = tmp_path / "agentapp"
    d.mkdir()
    (d / "app.py").write_text("from flask import request\n" + source, encoding="utf-8")
    findings = run_scan(d).findings
    flagged = [f for f in findings if f.rule_id == "PI-AGENT-HANDOFF"]
    if expect_finding:
        assert len(flagged) == 1, findings
        assert flagged[0].severity == "high"
    else:
        assert flagged == []


# -- audit: taint precision (cast / sanitizer / flow-sensitivity) ------------

_GRAPH = (
    "ops = Agent(name='ops', tools=[delete_files])\n"
    "triage = Agent(name='triage', tools=[], handoffs=[ops])\n"
)


def test_cast_input_is_silent():
    """`Runner.run(triage, int(x))` - a cast constrains the value; not a path."""
    src = (
        TOOLS + _GRAPH + ("def handle():\n    return Runner.run(triage, int(request.json['q']))\n")
    )
    assert _findings(src) == []


def test_sanitized_input_is_silent():
    """A name-matched sanitizer neutralizes the run input (precision-first: this
    rule gates CI, so it trusts the sanitizer rather than risk a false break)."""
    src = (
        TOOLS
        + _GRAPH
        + (
            "def sanitize(x):\n    return x.strip()\n"
            "def handle():\n    return Runner.run(triage, sanitize(request.json['q']))\n"
        )
    )
    assert _findings(src) == []


def test_unconditional_clean_reassignment_kills_taint():
    """`q = request.json[...]; q = 'const'; run(triage, q)` - q is clean at the
    run site. The old flow-insensitive pass never cleared it (false positive)."""
    src = (
        TOOLS
        + _GRAPH
        + (
            "def handle():\n"
            "    q = request.json['q']\n"
            "    q = 'fixed task'\n"
            "    return Runner.run(triage, q)\n"
        )
    )
    assert _findings(src) == []


def test_conditional_clean_reassignment_does_not_kill_taint():
    """A clean reassignment on ONE branch does not prove the value is clean on
    the path reaching the run site - must still flag (recall preserved)."""
    src = (
        TOOLS
        + _GRAPH
        + (
            "def handle(cond):\n"
            "    q = request.json['q']\n"
            "    if cond:\n"
            "        q = 'safe'\n"
            "    return Runner.run(triage, q)\n"
        )
    )
    assert len(_findings(src)) == 1
