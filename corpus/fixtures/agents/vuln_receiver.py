"""Multi-agent injection (agent.run form). MUST FLAG PI-AGENT-HANDOFF at `ops`."""

import subprocess

from agents import Agent, function_tool
from flask import request


@function_tool
def run_cmd(cmd):
    subprocess.run(cmd, shell=True)


ops = Agent(name="ops", tools=[run_cmd])
triage = Agent(name="triage", tools=[], handoffs=[ops])


def handle():
    return triage.run(request.json["q"])
