"""Project-local LLM wrapper (multi-hop fixture: the LLM call lives here)."""

from openai import OpenAI

client = OpenAI()


def ask_llm(prompt: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content
