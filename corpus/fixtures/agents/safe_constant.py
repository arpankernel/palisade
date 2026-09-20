"""Dangerous handoff exists, but the run input is a constant. MUST STAY SILENT."""
import shutil

from agents import Agent, Runner, function_tool
from flask import request


@function_tool
def delete_files(path):
    shutil.rmtree(path)


ops = Agent(name="ops", tools=[delete_files])
triage = Agent(name="triage", tools=[], handoffs=[ops])


def handle():
    _ = request.json  # mints a source so the target is scored, not skipped
    return Runner.run(triage, "run the nightly cleanup")
