# SAFE: a developer-controlled constant prompt reaching exec.
# There is no untrusted source, so taint never starts and nothing may flag.
from openai import OpenAI

client = OpenAI()


def nightly_report():
    resp = client.chat.completions.create(
        messages=[{"role": "user", "content": "print yesterday's date"}]
    )
    exec(resp.choices[0].message.content)  # noqa: S102
