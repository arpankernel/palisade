"""Mappings to the standards security teams file findings under.

Names and URLs were checked against the sources (genai.owasp.org and
cwe.mitre.org, CWE 4.20) when this table was written. Every rule maps to:

- CWE-1427 (prompt injection itself) and, where model output reaches a sink,
  CWE-1426 (unvalidated generative-AI output), plus the sink's classic CWE;
- OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection, and the
  category for what the output does (LLM05 Improper Output Handling, LLM06
  Excessive Agency).
"""

from __future__ import annotations

OWASP_LLM_2025: dict[str, tuple[str, str]] = {
    "LLM01:2025": (
        "Prompt Injection",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    ),
    "LLM05:2025": (
        "Improper Output Handling",
        "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
    ),
    "LLM06:2025": (
        "Excessive Agency",
        "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    ),
}

CWE_NAMES: dict[str, str] = {
    "CWE-78": "OS Command Injection",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-441": "Unintended Proxy or Intermediary ('Confused Deputy')",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1426": "Improper Validation of Generative AI Output",
    "CWE-1427": "Improper Neutralization of Input Used for LLM Prompting",
}


def sarif_cwe_tag(cwe: str) -> str:
    """GitHub code scanning's CWE tag form: `external/cwe/cwe-078`."""
    number = cwe.split("-", 1)[1]
    return f"external/cwe/cwe-{int(number):03d}"


def sarif_owasp_tag(category: str) -> str:
    """`LLM01:2025` -> `external/owasp-llm/llm01-2025`, mirroring the CWE tag form."""
    return "external/owasp-llm/" + category.lower().replace(":", "-")


def owasp_url(category: str) -> str | None:
    entry = OWASP_LLM_2025.get(category)
    return entry[1] if entry else None


def label(cwe: list[str], owasp: list[str]) -> str:
    """One-line human form, e.g. `CWE-94, CWE-1426 · OWASP LLM01:2025, LLM05:2025`."""
    parts = []
    if cwe:
        parts.append(", ".join(cwe))
    if owasp:
        parts.append("OWASP " + ", ".join(owasp))
    return " · ".join(parts)
