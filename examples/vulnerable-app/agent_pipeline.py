"""Multi-hop fixture: source in app.py, LLM in llm_utils.py, sink in
executor.py — this module is the middle hop."""

from executor import execute_plan
from llm_utils import ask_llm


def run_agent(goal: str) -> str:
    plan = ask_llm(f"Write Python code to accomplish: {goal}")
    return execute_plan(plan)
