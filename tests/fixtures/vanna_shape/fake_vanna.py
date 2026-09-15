"""Minimal offline mirror of the Vanna v0.5.5 CVE-2024-5565 shape
(vanna/base/base.py): a library whose public `ask(question)` flows through
an abstract provider LLM method and a cosmetic "sanitizer" into exec.

Kept structurally faithful on the four points that matter:
- untrusted input is a public-method PARAMETER (library entry),
- the LLM call is `self.submit_prompt(...)`, abstract in the base class,
- `_sanitize_plotly_code` only strips fig.show() — a sanitizer in name only,
- the sink is `exec(plotly_code, globals(), ldict)`.
"""


class FakeVannaBase:
    def ask(self, question: str):
        plotly_code = self.generate_plotly_code(question=question)
        fig = self.get_plotly_figure(plotly_code=plotly_code)
        return fig

    def generate_plotly_code(self, question: str, **kwargs) -> str:
        message_log = [
            self.system_message("You are a plotly expert. Respond with code only."),
            self.user_message(question),
        ]
        plotly_code = self.submit_prompt(message_log, kwargs=kwargs)
        return self._sanitize_plotly_code(self._extract_python_code(plotly_code))

    def submit_prompt(self, prompt, **kwargs) -> str:
        """Abstract: implemented per LLM provider in subclasses."""
        raise NotImplementedError

    def system_message(self, message: str) -> dict:
        return {"role": "system", "content": message}

    def user_message(self, message: str) -> dict:
        return {"role": "user", "content": message}

    def _extract_python_code(self, markdown_string: str) -> str:
        return markdown_string

    def _sanitize_plotly_code(self, raw_plotly_code: str) -> str:
        # Cosmetic only — exactly the defense CVE-2024-5565 walked through.
        plotly_code = raw_plotly_code.replace("fig.show()", "")
        return plotly_code

    def get_plotly_figure(self, plotly_code: str):
        ldict = {}
        exec(plotly_code, globals(), ldict)  # noqa: S102 — the CVE sink shape
        fig = ldict.get("fig", None)
        return fig
