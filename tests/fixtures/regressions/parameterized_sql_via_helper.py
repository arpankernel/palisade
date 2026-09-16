# SAFE: model output is bound as a query PARAMETER, never concatenated into
# the statement. The shape looks alarming (LLM output reaching execute) but
# the value can only ever be data.
from flask import request
from openai import OpenAI

client = OpenAI()


def lookup(cursor):
    description = request.json["description"]
    resp = client.chat.completions.create(messages=[{"role": "user", "content": description}])
    product = resp.choices[0].message.content
    cursor.execute("SELECT * FROM products WHERE name = ?", (product,))
    return cursor.fetchall()
