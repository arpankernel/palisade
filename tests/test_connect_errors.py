"""A surface that refuses to connect is the user's situation, not a crash.

`cli.run` ends in a last-resort handler that prints "internal error ...
please report it" and exits 3. That is right for a bug and wrong for a
mistyped webhook, an expired token, or an OAuth app this build has not
registered - all of which are ordinary, all of which already carry a
sentence saying what to do next.

Every one of those used to reach the exit-3 handler, so the first thing a
new user saw was Palisade calling its own normal behaviour a bug. These
tests pin the boundary: exit 2, the sentence, and no bug report.
"""

from __future__ import annotations

import inspect
import pkgutil
import subprocess
import sys

import pytest

import palisade_sec.connect as connect_pkg
from palisade_sec import cli
from palisade_sec.connect.errors import ConnectError
from palisade_sec.connect.github import GitHubError
from palisade_sec.connect.http import HttpError
from palisade_sec.connect.pr import PrError
from palisade_sec.connect.slack import SlackError
from palisade_sec.connect.store import CredentialError

# Every one of these is raised on purpose, with a message written for a
# human, so none of them may be presented as a crash.
DELIBERATE = [CredentialError, GitHubError, HttpError, PrError, SlackError]


@pytest.mark.parametrize("exc", DELIBERATE, ids=lambda e: e.__name__)
def test_deliberate_errors_are_connect_errors(exc: type[Exception]) -> None:
    assert issubclass(exc, ConnectError)


def test_every_exception_in_the_package_is_a_connect_error() -> None:
    """The guard that makes the fix hold: a sixth surface added later cannot
    quietly reintroduce an exception that exits 3."""
    found: dict[str, type] = {}
    for mod_info in pkgutil.iter_modules(connect_pkg.__path__):
        module = __import__(f"{connect_pkg.__name__}.{mod_info.name}", fromlist=["_"])
        for name, obj in vars(module).items():
            if (
                inspect.isclass(obj)
                and issubclass(obj, Exception)
                and obj.__module__.startswith(connect_pkg.__name__)
            ):
                found[f"{obj.__module__}.{name}"] = obj
    assert found, "no exception classes discovered - the walk is broken"
    stragglers = sorted(k for k, v in found.items() if not issubclass(v, ConnectError))
    assert not stragglers, (
        f"these must subclass ConnectError or they will be reported as bugs: {stragglers}"
    )


@pytest.mark.parametrize("backend", ["typesafe", "anthropic", "openai_compatible"])
def test_a_missing_llm_key_points_at_connect_llm(
    backend: str, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """`connect llm` is how you set a key in 0.6.0, so the error you hit
    before you know the command exists has to name it. Two of the three
    backends still sent people to edit a .env instead - including the
    default, which is the one a first-time `audit` uses."""
    from palisade_sec.judge.config import BACKEND_ENV, JudgeError, get_backend

    monkeypatch.chdir(tmp_path)  # no .env to pick up
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("PALISADE_NO_KEYRING", "1")
    monkeypatch.setenv(BACKEND_ENV, backend)
    for name in ("TYPESAFE_API_KEY", "ANTHROPIC_API_KEY", "PALISADE_JUDGE_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(JudgeError) as exc:
        get_backend()
    assert "palisade-sec connect llm" in str(exc.value), str(exc.value)


def _run(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["palisade-sec", *argv])
    monkeypatch.delenv("PALISADE_DEBUG", raising=False)
    with pytest.raises(SystemExit) as exit_info:
        cli.run()
    return int(exit_info.value.code or 0)


def test_connect_error_exits_2_and_keeps_its_sentence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> None:
        raise SlackError("that does not look like a Slack incoming webhook.")

    monkeypatch.setattr(cli, "app", boom)
    code = _run(monkeypatch, ["connect", "slack"])
    err = capsys.readouterr().err
    assert code == 2
    assert "that does not look like a Slack incoming webhook." in err
    assert "internal error" not in err
    assert "report it" not in err


def test_a_real_bug_still_exits_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The mirror image: the exit-3 handler must still be there. Without
    this, 'catch ConnectError' could widen to 'catch Exception' and CI
    would lose the crashed/found-a-HIGH distinction."""

    def boom() -> None:
        raise ValueError("genuinely unexpected")

    monkeypatch.setattr(cli, "app", boom)
    code = _run(monkeypatch, ["scan", "."])
    err = capsys.readouterr().err
    assert code == 3
    assert "internal error" in err


def test_debug_still_reraises_a_connect_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """PALISADE_DEBUG=1 is how a maintainer gets the traceback; a handled
    ConnectError must not swallow it."""

    def boom() -> None:
        raise SlackError("webhook rejected")

    monkeypatch.setattr(cli, "app", boom)
    monkeypatch.setattr(sys, "argv", ["palisade-sec", "connect", "slack"])
    monkeypatch.setenv("PALISADE_DEBUG", "1")
    with pytest.raises(SlackError):
        cli.run()


def test_first_run_without_an_oauth_app_is_not_reported_as_a_bug(tmp_path) -> None:
    """End to end through the installed entry point, on the exact path a new
    user hits: no `gh` login to reuse, and no OAuth App registered yet."""
    env = {
        "PATH": "/usr/bin:/bin",  # no `gh` on it
        "HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "PALISADE_NO_KEYRING": "1",
        "PALISADE_GITHUB_CLIENT_ID": "",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "palisade_sec.cli", "connect", "github", "--no-gh"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 2, output
    assert "gh auth login" in output
    assert "internal error" not in output
