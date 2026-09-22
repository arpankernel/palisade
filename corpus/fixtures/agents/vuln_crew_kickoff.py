"""Multi-agent injection via crew.kickoff(), not an agent's own .run().
MUST FLAG PI-AGENT-HANDOFF at `executor`."""

import subprocess

from crewai import Agent, Crew
from crewai.tools import tool
from flask import request


@tool
def shell(cmd):
    subprocess.run(cmd, shell=True)


researcher = Agent(role="researcher", tools=[])
executor = Agent(role="executor", tools=[shell])

crew = Crew(agents=[researcher, executor])


def handle():
    topic = request.json["topic"]
    return crew.kickoff(inputs={"topic": topic})
