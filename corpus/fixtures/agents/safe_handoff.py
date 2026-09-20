"""Untrusted input, but the only handoff target is a safe agent. MUST STAY SILENT."""

from agents import Agent, Runner, function_tool
from flask import request


@function_tool
def greet(name):
    return f"hi {name}"


helper = Agent(name="helper", tools=[greet])
triage = Agent(name="triage", tools=[], handoffs=[helper])


def handle():
    return Runner.run(triage, request.json["q"])
