"""Multi-hop fixture: the dangerous sink lives here."""


def execute_plan(code: str) -> str:
    exec(code)  # noqa: S102 — the vulnerability under test (multi-hop)
    return "ok"
