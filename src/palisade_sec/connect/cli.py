"""`palisade-sec connect` and friends: set the tool up from the terminal.

These are the only commands that talk to the network on their own behalf.
Each one verifies the credential before storing it, so "connected" means
"checked", not "typed in". Secrets are never echoed back.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from palisade_sec.connect import github as gh
from palisade_sec.connect import slack as sl
from palisade_sec.connect.http import HttpError, request_json
from palisade_sec.connect.store import (
    GITHUB_TOKEN,
    LLM_ENDPOINT,
    LLM_KEY,
    LLM_MODEL,
    LLM_PROVIDER,
    SLACK_WEBHOOK,
    CredentialError,
    delete_credential,
    get_credential,
    set_credential,
    storage_backend,
)

connect_app = typer.Typer(
    name="connect",
    help="Connect GitHub, Slack and an LLM provider. Credentials go to your OS keychain.",
    no_args_is_help=True,
)

PROVIDERS = ("typesafe", "anthropic", "openai_compatible")


def _console() -> Console:
    return Console(highlight=False)


@connect_app.command("github")
def connect_github(
    token: str | None = typer.Option(
        None, "--token", help="Use this token instead of gh/device flow (read from stdin if '-')."
    ),
    use_gh: bool = typer.Option(
        True, "--gh/--no-gh", help="Reuse the GitHub CLI's token when it is logged in."
    ),
) -> None:
    """Connect GitHub (for `palisade-sec pr`). Reuses `gh` when available."""
    console = _console()
    if token == "-":
        token = typer.prompt("GitHub token", hide_input=True)
    source = "flag"
    if not token and use_gh:
        found = gh.gh_cli_token()
        if found:
            console.print("[dim]found a logged-in `gh` CLI; using its token[/dim]")
            token, source = found, "gh"
    if not token:
        code = gh.start_device_flow()
        console.print(
            f"\n  Open [bold]{code.verification_uri}[/bold] and enter the code "
            f"[bold]{code.user_code}[/bold]\n"
        )
        console.print("[dim]waiting for approval…[/dim]")
        token, source = gh.poll_device_flow(code), "device flow"

    identity = gh.verify(token, source)
    if not gh.can_open_prs(identity):
        raise typer.BadParameter(
            f"that token has scopes {identity.scopes or ['(none)']} - opening pull requests "
            "needs `repo` (or a fine-grained token with Contents and Pull requests write)."
        )
    where = set_credential(GITHUB_TOKEN, token)
    console.print(
        f"[green]✓[/green] GitHub connected as [bold]{identity.login}[/bold] "
        f"(via {source}) -> stored in {where}"
    )


@connect_app.command("slack")
def connect_slack(
    webhook: str | None = typer.Option(None, "--webhook", help="Slack incoming webhook URL."),
    test: bool = typer.Option(True, "--test/--no-test", help="Post a test message to the channel."),
) -> None:
    """Connect Slack (for `palisade-sec notify --slack`) with an incoming webhook."""
    console = _console()
    url = webhook or typer.prompt("Slack incoming webhook URL", hide_input=True)
    url = url.strip()
    sl.validate_webhook(url)
    if test:
        sl.post(url, "Palisade is connected to this channel.")
        console.print("[dim]posted a test message[/dim]")
    where = set_credential(SLACK_WEBHOOK, url)
    console.print(f"[green]✓[/green] Slack connected -> stored in {where}")


@connect_app.command("llm")
def connect_llm(
    provider: str = typer.Option(
        "anthropic", "--provider", help=f"One of: {', '.join(PROVIDERS)}."
    ),
    key: str | None = typer.Option(None, "--key", help="API key (prompted if omitted)."),
    endpoint: str | None = typer.Option(None, "--endpoint", help="Override the base URL."),
    model: str | None = typer.Option(None, "--model", help="Override the model id."),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Check the key works."),
) -> None:
    """Connect an LLM provider for the judgment layer (`audit`, `review`).

    The offline core (scan, map, baseline, fix) never uses this.
    """
    console = _console()
    provider = provider.strip().lower()
    if provider not in PROVIDERS:
        raise typer.BadParameter(f"--provider must be one of {', '.join(PROVIDERS)}")
    if provider == "openai_compatible" and not endpoint:
        raise typer.BadParameter("--endpoint is required for openai_compatible")
    api_key = key or typer.prompt(f"{provider} API key", hide_input=True)
    api_key = api_key.strip()
    if not api_key:
        raise typer.BadParameter("no key given")

    if verify:
        _verify_llm(console, provider, api_key, endpoint, model)

    where = set_credential(LLM_KEY, api_key)
    set_credential(LLM_PROVIDER, provider)
    if endpoint:
        set_credential(LLM_ENDPOINT, endpoint)
    if model:
        set_credential(LLM_MODEL, model)
    console.print(f"[green]✓[/green] {provider} connected -> stored in {where}")
    # markup=False: rich reads `[judge]` as a style tag and drops it, which
    # turned this into `pip install 'palisade-sec'` - a command that succeeds
    # and installs nothing, leaving the user stuck with no error to search for.
    console.print(
        "used by `audit` and `review`; install the extra with "
        "`pip install 'palisade-sec[judge]'` if you have not already",
        markup=False,
        style="dim",
    )


def _verify_llm(
    console: Console, provider: str, key: str, endpoint: str | None, model: str | None
) -> None:
    """One cheap call to prove the key works, using stdlib HTTP only."""
    try:
        if provider == "anthropic":
            from palisade_sec.judge.anthropic import API_VERSION, DEFAULT_ENDPOINT, DEFAULT_MODEL

            request_json(
                f"{(endpoint or DEFAULT_ENDPOINT).rstrip('/')}/v1/messages",
                method="POST",
                headers={"x-api-key": key, "anthropic-version": API_VERSION},
                body={
                    "model": model or DEFAULT_MODEL,
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "ping"}],
                },
            )
        elif provider == "openai_compatible":
            request_json(
                f"{(endpoint or '').rstrip('/')}/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        else:  # typesafe has no cheap probe endpoint
            console.print("[dim]stored without a live check (typesafe has no probe endpoint)[/dim]")
            return
    except HttpError as exc:
        if exc.status in (401, 403):
            raise typer.BadParameter(f"{provider} rejected that key ({exc.status}).") from None
        raise typer.BadParameter(f"could not verify the key: {exc}") from None
    console.print("[dim]key verified[/dim]")


def connections_cmd() -> None:
    """Show what is connected, where each credential comes from, redacted."""
    console = _console()
    table = Table(title=None, show_edge=False, pad_edge=False)
    for col in ("surface", "status", "source", "value", "used by"):
        table.add_column(col)

    rows = [
        ("github", GITHUB_TOKEN, "pr"),
        ("slack", SLACK_WEBHOOK, "notify --slack"),
        ("llm", LLM_KEY, "audit, review"),
    ]
    for name, key, used in rows:
        try:
            found = get_credential(key)
        except CredentialError as exc:
            console.print(f"[yellow]warning:[/yellow] {exc}")
            found = None
        if name == "github" and not found:
            token = gh.gh_cli_token()
            if token:
                from palisade_sec.connect.store import Resolved

                found = Resolved(GITHUB_TOKEN, token, "gh")
        extra = ""
        if name == "llm" and found:
            provider = get_credential(LLM_PROVIDER)
            extra = f" ({provider.value})" if provider else ""
        status = "[green]connected[/green]" if found else "[dim]not connected[/dim]"
        table.add_row(
            name + extra,
            status,
            found.source if found else "-",
            found.display if found else "-",
            used,
        )
    console.print(table)
    console.print(f"[dim]storage: {storage_backend()}[/dim]")


def disconnect_cmd(surface: str) -> None:
    """Remove a stored credential."""
    console = _console()
    keys = {
        "github": [GITHUB_TOKEN],
        "slack": [SLACK_WEBHOOK],
        "llm": [LLM_KEY, LLM_PROVIDER, LLM_ENDPOINT, LLM_MODEL],
    }.get(surface)
    if not keys:
        raise typer.BadParameter("surface must be one of: github, slack, llm")
    # A list, not a generator: `any()` short-circuits, which left the
    # provider and model behind after 'disconnecting' the llm surface.
    removed = any([delete_credential(k) for k in keys])  # noqa: C419
    if removed:
        console.print(f"[green]✓[/green] {surface} disconnected")
    else:
        console.print(f"[dim]{surface} was not connected[/dim]")
    if surface == "github" and gh.gh_cli_token():
        console.print(
            "[dim]note: the `gh` CLI is still logged in and will be used as a fallback[/dim]"
        )
