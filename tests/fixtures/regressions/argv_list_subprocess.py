# SAFE: model output is one element of an argument LIST with no shell, so it
# cannot inject a command. Only the string / shell=True form is dangerous.
import subprocess

from flask import request
from openai import OpenAI

client = OpenAI()


def ping_host():
    where = request.json["where"]
    resp = client.chat.completions.create(messages=[{"role": "user", "content": where}])
    host = resp.choices[0].message.content.strip()
    subprocess.run(["ping", "-c", "1", host], check=False)
