"""The version lives in two files, and nothing checked that they agree.

`pyproject.toml` decides what PyPI receives, and the release workflow compares
the git tag against it. `palisade_sec.__version__` decides what the artifacts
say: `--version`, the baseline JSON, the fix plan header, the JSON and markdown
reports, the HTTP user agent, and the SARIF `tool.driver.version` that GitHub
code scanning stores against every alert.

So bumping one and not the other publishes a release whose own artifacts
misreport which release they came from - and the release gate would not notice,
because it only ever reads `pyproject.toml`. Found while cutting 0.6.1, where
the first edit touched only `pyproject.toml`.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import palisade_sec
from palisade_sec.report import sarif

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"

_SEMVER = re.compile(r"^\d+\.\d+\.\d+([-.+][0-9A-Za-z.-]+)?$")


def _packaged_version() -> str:
    return str(tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"])


def test_pyproject_and_dunder_version_agree() -> None:
    """The one assertion that would have caught the 0.6.1 slip."""
    assert palisade_sec.__version__ == _packaged_version(), (
        f"__init__.py says {palisade_sec.__version__}, pyproject.toml says "
        f"{_packaged_version()}. The release gate only reads pyproject, so this "
        "ships artifacts that misreport their own version."
    )


def test_the_version_is_a_real_version() -> None:
    """Guards the test above from passing because both are empty or a
    placeholder."""
    assert _SEMVER.match(palisade_sec.__version__), palisade_sec.__version__
    assert _SEMVER.match(_packaged_version()), _packaged_version()


def test_sarif_reports_the_package_version() -> None:
    """SARIF's version is retained by GitHub against every alert, so it is the
    consumer where a wrong version is hardest to correct after the fact."""
    doc = json.loads(sarif.to_sarif([], files_scanned=0))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["version"] == palisade_sec.__version__
    assert driver["version"] == _packaged_version()
