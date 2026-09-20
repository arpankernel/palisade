"""Multi-agent injection (Runner.run form). MUST FLAG PI-AGENT-HANDOFF at `ops`."""
import shutil

from agents import Agent, Runner, function_tool
from flask import request


@function_tool
def delete_files(path):
    shutil.rmtree(path)


ops = Agent(name="ops", tools=[delete_files])
triage = Agent(name="triage", tools=[], handoffs=[ops])


def handle():
    task = request.json["task"]
    return Runner.run(triage, task)
