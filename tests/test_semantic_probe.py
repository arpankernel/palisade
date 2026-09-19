"""PROBE is deterministic and offline: given source, it must find the right
tools and the exact capabilities their bodies exercise - no judgments, no
network. These tests never touch TypeSafe."""

from __future__ import annotations

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.probe import harvest_tools

SOURCE = """
import os
import subprocess
import stripe
from langchain.tools import tool
from agents import function_tool


@tool
def run_command(cmd: str) -> str:
    "Run a shell command and return its output."
    subprocess.run(cmd, shell=True)
    return os.system(cmd)


@function_tool
def charge_card(customer: str, amount: int):
    "Charge a customer's card."
    return stripe.PaymentIntent.create(customer=customer, amount=amount)


@tool
def format_name(first: str, last: str) -> str:
    "Pure computation - no capabilities."
    return f"{first} {last}".title()


def internal_helper(cmd: str):
    # Not a tool (no decorator) - must NOT be harvested even though it is dangerous.
    os.system(cmd)
"""


def _lower(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return [mod]


def test_harvests_only_decorated_tools():
    tools = harvest_tools(_lower(SOURCE))
    names = {t.name for t in tools}
    assert names == {"run_command", "charge_card", "format_name"}
    assert "internal_helper" not in names  # dangerous, but not a tool


def test_shell_tool_capabilities_and_evidence():
    tools = {t.name: t for t in harvest_tools(_lower(SOURCE))}
    shell = tools["run_command"]
    assert shell.capabilities == ["shell"]
    # both subprocess.run and os.system are recorded as grounded evidence
    paths = {h.func_path for h in shell.capability_hits}
    assert paths == {"subprocess.run", "os.system"}
    assert all(h.snippet for h in shell.capability_hits)
    assert shell.docstring.startswith("Run a shell command")


def test_payments_capability():
    tools = {t.name: t for t in harvest_tools(_lower(SOURCE))}
    assert "payments" in tools["charge_card"].capabilities


def test_pure_tool_has_no_capabilities():
    tools = {t.name: t for t in harvest_tools(_lower(SOURCE))}
    assert tools["format_name"].capabilities == []
    assert tools["format_name"].capability_hits == []


def test_agent_dot_tool_decorator_matches():
    src = (
        "from pydantic_ai import Agent\n"
        "agent = Agent()\n"
        "import shutil\n"
        "@agent.tool\n"
        "def wipe(path: str):\n"
        "    shutil.rmtree(path)\n"
    )
    tools = harvest_tools(_lower(src))
    assert len(tools) == 1
    assert tools[0].name == "wipe"
    assert tools[0].capabilities == ["file_write"]
