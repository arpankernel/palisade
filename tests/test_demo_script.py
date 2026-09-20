"""scripts/demo.sh must stop with a clear, key-free message when no judgment key
is configured, before it makes any endpoint call. This runs the script with an
empty env file and no keys, so it never touches the network."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEMO = REPO / "scripts" / "demo.sh"


def test_demo_script_exists_and_executable():
    assert DEMO.is_file()
    assert os.access(DEMO, os.X_OK)


def test_demo_fails_clearly_without_a_key():
    env = {
        "PATH": os.environ.get("PATH", ""),
        "ENV_FILE": os.devnull,  # ignore any local .env
        "PALISADE_JUDGE_BACKEND": "typesafe",
    }
    # Ensure keys are absent from the child environment.
    proc = subprocess.run(
        ["bash", str(DEMO)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO),
    )
    assert proc.returncode != 0
    assert "TYPESAFE_API_KEY" in proc.stderr
    # It must fail before ever invoking the CLI / touching the network.
    assert "scan" not in proc.stdout


def test_demo_openai_backend_names_its_key():
    env = {
        "PATH": os.environ.get("PATH", ""),
        "ENV_FILE": os.devnull,
        "PALISADE_JUDGE_BACKEND": "openai_compatible",
    }
    proc = subprocess.run(
        ["bash", str(DEMO)], capture_output=True, text=True, env=env, cwd=str(REPO)
    )
    assert proc.returncode != 0
    assert "PALISADE_JUDGE_API_KEY" in proc.stderr
