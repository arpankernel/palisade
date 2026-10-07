"""The launch surfaces may not publish precision without recall.

This is the rule that took three measurements to earn. Precision 1.000 over
40,466 files is true and, quoted alone, it is an advertisement for a scanner
that finds almost nothing: a tool that reports nothing has perfect precision for
free. Held-out recall is 0.000 over 45 independent observations, and a reader
who sees one number without the other has been misled by omission.

Prose has no tests, which is how ten places came to quote a recall figure
measured on the engine's own training material for months. So the rule is
mechanical here: any user-facing surface that states the precision claim must
state the held-out figure too, with its denominator.

Scoped to the surfaces a user or a model actually reads. The CHANGELOG is
excluded: it is a record of what was true at each release, and rewriting history
to satisfy a present-day rule would be the opposite of honest.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SURFACES = [
    "README.md",
    "llms.txt",
    "website/index.html",
    "website/roadmap.html",
    "docs/PRD.md",
    "docs/roadmap.md",
    "docs/proof-scans.md",
    "docs/typesafe-integration.md",
    "docs-site/src/content/docs/roadmap.md",
    "docs-site/src/content/docs/proof-scans.md",
    # The docs site's own tagline and meta description. Not prose, but it is
    # the first line a reader and a search engine see, and it carried a retired
    # framing for a full release after every .md file had been corrected.
    "docs-site/astro.config.mjs",
]

# The precision claim in any of the spellings the surfaces actually use.
_PRECISION = re.compile(r"precision[^.\n]{0,40}1\.000|zero false positives|0 false positives", re.I)
# The held-out figure, and its denominator - a bare "0.000" would let someone
# satisfy this rule while leaving the reader to assume n=2.
_HELD_OUT = re.compile(r"held-out", re.I)
_DENOMINATOR = re.compile(r"\b45\b|\b98\b")


def _files() -> list[Path]:
    return [ROOT / s for s in SURFACES if (ROOT / s).is_file()]


def test_the_surfaces_exist() -> None:
    """Vacuity guard. If the paths drift, every test below passes on an empty
    list and the rule silently stops applying."""
    found = _files()
    assert len(found) >= 8, f"only found {[str(f) for f in found]}"


@pytest.mark.parametrize("rel", SURFACES)
def test_precision_is_never_published_alone(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    text = path.read_text(encoding="utf-8")
    if not _PRECISION.search(text):
        return  # a surface that makes no precision claim owes nothing
    assert _HELD_OUT.search(text), (
        f"{rel} states the precision claim and never mentions held-out recall. "
        "A scanner that reports nothing has perfect precision for free, so the "
        "two numbers are published together or not at all."
    )
    assert _DENOMINATOR.search(text), (
        f"{rel} mentions held-out recall without its denominator. 0.000 over 45 "
        "independent observations is a far stronger statement than 0.000 over "
        "2, and a bare figure lets a reader assume either."
    )


def test_the_detector_claim_does_not_overreach(rel: str = "README.md") -> None:
    """The narrow claim, pinned where a reader meets it first.

    Three engine passes each moved held-out recall by zero paths, so a claim to
    find the agent-framework shape is one a first scan would embarrass. The
    README has to say what is not covered, in the open.
    """
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert "does not currently catch" in text or "does not catch" in text, (
        "the README must state the shape Palisade does NOT catch - it is the "
        "difference between a limit a user reads and a limit a user discovers"
    )
    assert "agent-framework" in text or "agent framework" in text, (
        "the uncovered shape must be named, not gestured at"
    )


def test_the_direction_of_error_is_published() -> None:
    """Ground truth is known-incomplete and the bias runs one way, so the
    recall figure is generous rather than conservative. A reader who later
    finds an unlabelled sibling should find that we said so first."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "known-incomplete" in text or "overestimate" in text, (
        "the README must carry the direction of the ground-truth error"
    )


# ---------------------------------------------------------------------------
# The judged layer is advisory and uncalibrated, and must say so
# ---------------------------------------------------------------------------
#
# The recall pair is not the only number a reader can over-read. `audit` and
# `review` ship in 0.7.0 with their calibration still a 10-case seed corpus
# (n=4-6 per signal) - not a benchmark result - and the judged layer is the part
# of this release most likely to be read as "the AI decides whether you are
# safe". It is the same failure as quoting precision alone: a number that sounds
# like evidence, presented without the thing that makes it weak.
#
# Substance, not vocabulary. Nothing requires the word "uncalibrated"; a surface
# that says "preliminary, measured on a seed corpus, not a benchmark result"
# has told the reader more than the word would.

# The FEATURE, not the English words. A first draft matched `\baudit\b` and
# `\breview\b`, which fired on "a 2026-09-22 audit of the clean repos" and on
# "review, then either fix or baseline" - ordinary prose about auditing and
# reviewing, nothing to do with the judged layer. A guard that cries wolf on
# plain English gets widened until it means nothing.
_JUDGED = re.compile(
    r"palisade-sec\s+(audit|review)|`audit`|`review`|judgment layer|judged (layer|check|signal)",
    re.I,
)
_ADVISORY = re.compile(r"advisory", re.I)
_UNCALIBRATED = re.compile(
    r"uncalibrated|not calibrated|preliminary|seed corpus|seed-corpus|not a benchmark result",
    re.I,
)


@pytest.mark.parametrize("rel", SURFACES)
def test_the_judged_layer_is_labelled_advisory_and_uncalibrated(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    if path.suffix in {".mjs", ".js", ".json", ".toml", ".yaml", ".yml"}:
        # Config, not prose. The docs site's sidebar has a link reading
        # "Judgment layer" and a link is not a description - the page it points
        # at carries the caveat, and demanding the full "advisory, preliminary
        # calibration" sentence inside a nav label would make the rule absurd
        # and get it deleted. Positioning and CVE claims still apply here,
        # because a tagline IS a claim.
        pytest.skip(f"{rel} is config; the judged-layer caveat belongs in prose")
    text = path.read_text(encoding="utf-8")
    if not _JUDGED.search(text):
        return  # a surface that never mentions the judged layer owes nothing
    assert _ADVISORY.search(text), (
        f"{rel} describes the judged layer and never calls it advisory. It is "
        "the part of this release most likely to be read as the tool deciding "
        "whether you are safe."
    )
    assert _UNCALIBRATED.search(text), (
        f"{rel} describes the judged layer without saying its calibration is "
        "preliminary. The signal is measured on a 10-case seed corpus, not a "
        "benchmark, and a reader cannot know that from the surface alone."
    )


def test_the_judged_caveat_guard_is_not_vacuous() -> None:
    """The regexes have to actually fire, or every assertion above passes on a
    surface that says nothing at all."""
    assert _JUDGED.search("run palisade-sec audit .")
    assert not _JUDGED.search("a 2026-09-22 audit of the clean repos found 7 paths")
    assert not _JUDGED.search("advisory severity: review, then fix or baseline")
    assert not _JUDGED.search("a precise static detector for one shape")
    assert _ADVISORY.search("the judged layer stays advisory")
    assert _UNCALIBRATED.search("calibration is preliminary")
    assert not _UNCALIBRATED.search("precision 1.000 with zero false positives")


# ---------------------------------------------------------------------------
# Positioning: building, not hiring, and not "is"
# ---------------------------------------------------------------------------
#
# "We're building the AI safety engineer for your codebase" is honest because
# of the verb. The complete role is roadmap; one verb of it ships. Two earlier
# framings claimed more than the measurements support and must not come back.

_RETIRED_FRAMINGS = (
    "AI Safety Engineer you hire",
    "applied agentic-safety infrastructure",
    # Found still live in the docs-site splash hero after every .md body had
    # been corrected: a third phrasing of the same overclaim, describing the
    # finished capability with no mention of what is not built. Exact-string
    # matching only catches the wordings someone remembered to add, which is
    # why the positive checks (hero says "building", boundary is named) carry
    # more weight than this list.
    "Instruments the boundary where AI systems take real-world actions",
)


@pytest.mark.parametrize("rel", SURFACES)
def test_no_surface_claims_the_whole_role_exists(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    text = path.read_text(encoding="utf-8")
    found = [f for f in _RETIRED_FRAMINGS if f.lower() in text.lower()]
    assert not found, (
        f"{rel} still carries a framing that claims the finished role: {found}. "
        "The verb is 'building' - three engine passes each moved held-out recall "
        "by zero paths, so a claim to be the safety engineer is one a first scan "
        "would embarrass."
    )


def test_the_landing_page_leads_with_building() -> None:
    """The hero is where the claim is made or overclaimed, so it is pinned."""
    text = (ROOT / "website/index.html").read_text(encoding="utf-8")
    assert "building the" in text.lower(), "the hero must say what is being built, not what exists"
    head = text[: text.index("</h1>") + 5] if "</h1>" in text else text[:4000]
    assert "safety engineer" in head.lower()


def test_the_landing_page_states_the_boundary_itself() -> None:
    """Not only in the docs. A visitor who never opens a doc has to be told
    which shape is uncovered, or the precision number reads as coverage."""
    text = (ROOT / "website/index.html").read_text(encoding="utf-8")
    assert "does not yet catch" in text or "not caught yet" in text, (
        "the landing page must name the uncovered shape in its own copy"
    )
    assert "agent framework" in text.lower(), "the uncovered shape must be named"


def test_the_landing_page_grounds_the_vision_in_the_same_view() -> None:
    """The subhead under the hero names the thing that actually ships. Vision as
    headline is only honest when the live product is in the same viewport."""
    text = (ROOT / "website/index.html").read_text(encoding="utf-8")
    hero = text[text.index("<h1") : text.index("</header>")]
    assert "v1 ships today" in hero, "the hero needs the grounding subhead, not just the vision"
    assert "roadmap" in hero.lower(), "the hero must point at what is NOT built"


# ---------------------------------------------------------------------------
# CVE claims must match the corpus
# ---------------------------------------------------------------------------
#
# Of the three CVEs that motivate the rule class, the corpus records exactly
# one as caught:
#
#   CVE-2024-5565  (Vanna)            found, both releases
#   CVE-2024-12366 (PandasAI)         MISSED - a documented false negative
#   CVE-2023-36258 (LangChain PAL)    never tested - not in the corpus at all
#
# All three are legitimate to cite as the family the rule targets. Only the
# first is legitimate to cite as a result, and the difference is one verb. This
# test exists because a draft of the launch copy listed all three as catches.

_PANDASAI = "CVE-2024-12366"
_LANGCHAIN = "CVE-2023-36258"


@pytest.mark.parametrize("rel", SURFACES)
def test_a_missed_cve_is_never_cited_without_its_outcome(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    text = path.read_text(encoding="utf-8")
    if _PANDASAI not in text:
        return
    assert "missed" in text.lower(), (
        f"{rel} cites {_PANDASAI} but never says it is missed. The corpus scores "
        "it as a false negative, so citing it among results overstates coverage - "
        "cite it as the family the rule targets, or state the outcome."
    )


@pytest.mark.parametrize("rel", SURFACES)
def test_an_untested_cve_is_only_cited_as_motivation(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    text = path.read_text(encoding="utf-8")
    if _LANGCHAIN not in text:
        return
    framing = ("targets", "family", "class", "motivat", "refs", "reference")
    assert any(w in text.lower() for w in framing), (
        f"{rel} cites {_LANGCHAIN}, which is not in the corpus and has never been "
        "measured. It may only appear as the family the rule targets, never as a "
        "result."
    )


# ---------------------------------------------------------------------------
# The honesty block replaces the trust signals a template would carry
# ---------------------------------------------------------------------------
#
# A product page of this shape has a slot for testimonials, customer logos and
# a usage counter. Palisade has none of those yet, and inventing them on a
# security tool is worse than leaving the slot empty: the whole pitch is that
# the numbers are real. So the slot carries the measurement instead, and these
# tests hold it to carrying all of it.

_PAGES_WITH_NUMBERS = ["website/index.html", "website/roadmap.html"]


@pytest.mark.parametrize("rel", _PAGES_WITH_NUMBERS)
def test_a_page_that_shows_the_pair_also_shows_the_direction_of_error(rel: str) -> None:
    """Both numbers together is necessary and not sufficient. 0.000 over 45
    reads as a floor; it is a ceiling, because the ground truth is incomplete
    and the gap runs one way."""
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    text = path.read_text(encoding="utf-8")
    if not _PRECISION.search(text):
        return
    assert "known-incomplete" in text or "overestimate" in text, (
        f"{rel} publishes the measured pair without the direction of the "
        "ground-truth error. A reader who later finds an unlabelled sibling "
        "should find that we said so first."
    )


def test_the_landing_page_carries_no_fabricated_trust_signals() -> None:
    """The slot where a template puts social proof. Until any of this is real,
    it stays empty and the measurement stands in its place."""
    text = (ROOT / "website/index.html").read_text(encoding="utf-8").lower()
    banned = [
        "testimonial",
        "trusted by",
        "loved by",
        "customers say",
        "developers trust",
        "join thousands",
        "used by thousands",
        "5-star",
    ]
    found = [b for b in banned if b in text]
    assert not found, (
        f"the landing page carries a trust signal with nothing behind it: {found}. "
        "A fake one on a security tool is worse than none."
    )
    # A star rating or a user count, in the shapes a template writes them.
    assert not re.search(
        r"\b\d[\d,.]*\s*(?:\+\s*)?(?:users|teams|developers|stars|downloads)\b", text
    ), "the landing page states a usage metric; none has been measured"


def test_the_landing_page_names_the_shipped_verb_and_the_unbuilt_ones() -> None:
    """The roadmap block is the only place the finished role may appear, and it
    has to appear beside what is not built, or it reads as a claim."""
    text = (ROOT / "website/index.html").read_text(encoding="utf-8")
    low = text.lower()
    assert "upcoming" in low, "the landing page must mark the unbuilt verbs as upcoming"
    if "complete ai safety engineer" in low:
        assert "destination" in low, (
            "the finished role may only appear as the destination, never as a "
            "description of what ships"
        )


def test_the_landing_page_publishes_no_dates() -> None:
    """No dates on the roadmap. A date is a promise, and nothing below SEE is
    far enough along to make one."""
    for rel in _PAGES_WITH_NUMBERS:
        path = ROOT / rel
        if not path.is_file():
            continue
        body = path.read_text(encoding="utf-8")
        body = body[body.index("<body") :] if "<body" in body else body
        assert not re.search(r"\b(Q[1-4]\s*20\d\d|20\d\d\s*Q[1-4])\b", body, re.I), (
            f"{rel} puts a quarter on the roadmap"
        )
        assert not re.search(
            r"\b(?:by|ships?|lands?|due)\s+(?:early|mid|late)?\s*20\d\d\b", body, re.I
        ), f"{rel} puts a year on the roadmap"


def test_the_shared_stylesheet_is_the_only_token_source() -> None:
    """Both pages carried their own copy of the palette, which is how they
    drifted apart the last time either was edited."""
    css = (ROOT / "website/styles.css").read_text(encoding="utf-8")
    assert "--accent:" in css, "the shared sheet must define the palette"
    for rel in _PAGES_WITH_NUMBERS:
        path = ROOT / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert 'href="./styles.css"' in text, f"{rel} does not use the shared stylesheet"
        page_css = "\n".join(
            text[m.end() : text.index("</style>", m.end())] for m in re.finditer(r"<style>", text)
        )
        assert "--accent:" not in page_css, (
            f"{rel} redefines the palette inline; it belongs in styles.css only"
        )


def test_the_cve_facts_still_match_the_corpus() -> None:
    """Vacuity guard, and a drift guard. If PandasAI's label ever becomes a
    true positive, the test above should be relaxed deliberately rather than
    left asserting something no longer true - so the premise is checked here.
    """
    import yaml

    doc = yaml.safe_load((ROOT / "corpus" / "repos.yaml").read_text(encoding="utf-8"))
    cves = {r["name"]: r.get("cve") for r in doc["repos"] if r.get("cve")}
    assert cves.get("pandasai-cve") == _PANDASAI, "the PandasAI corpus entry moved"
    assert cves.get("vanna-cve") == "CVE-2024-5565"
    assert _LANGCHAIN not in cves.values(), (
        f"{_LANGCHAIN} is now in the corpus - if it is measured, the motivation-only "
        "rule above should be revisited on purpose"
    )
    proof = (ROOT / "docs" / "proof-scans.md").read_text(encoding="utf-8")
    assert "**missed**" in proof, "proof-scans no longer records a miss; check the premise"
