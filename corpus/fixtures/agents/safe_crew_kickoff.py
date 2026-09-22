"""crew.kickoff() with untrusted input, but every agent is safe. MUST STAY SILENT."""

from crewai import Agent, Crew
from crewai.tools import tool
from flask import request


@tool
def greet(name):
    return f"hi {name}"


researcher = Agent(role="researcher", tools=[])
helper = Agent(role="helper", tools=[greet])

crew = Crew(agents=[researcher, helper])


def handle():
    topic = request.json["topic"]
    return crew.kickoff(inputs={"topic": topic})
