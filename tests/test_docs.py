"""
The written parts of Helix: the evidence spec must name every field a record
holds, and public text follows the house style (plain sentences, no long
dashes, no arrows in prose).
"""

import glob
import os
import re

import pytest

from osint import evidence

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = sorted(glob.glob(os.path.join(ROOT, "*.md")) + glob.glob(os.path.join(ROOT, "docs", "*.md"))
              + glob.glob(os.path.join(ROOT, "bench", "*.md")))

pytestmark = pytest.mark.skipif(not os.path.exists(os.path.join(ROOT, "docs", "EVIDENCE_SPEC.md")),
                                reason="documents are in the repository, not in the installed package")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def test_the_spec_names_every_field_of_a_scan_record():
    spec = _read("docs", "EVIDENCE_SPEC.md")
    record = evidence.build(
        username="janeroe", results=[{"platform": "A", "found": True, "url": "u", "page_sha256": "x" * 64,
                                      "recovered": "retry"}],
        platform_map={"A": {"url": "https://a.example/{username}"}}, started="t", finished="t",
        wall_seconds=1, argv=["helix"], concurrency=1, control=True, sites_file="s.json",
        pages={"_dir": "p", "pages": [], "_sha256": "y" * 64}, controls=3, purpose="test",
        collector="someone", switched_off={"count": 1, "list_updated_utc": "t"}, target_type="email")
    for key in record:
        assert f"`{key}" in spec, f"top-level field {key} is not in the spec"
    for section in ("attempt", "database", "summary"):
        for key in record[section]:
            assert key in spec, f"{section}.{key} is not in the spec"
    for key in record["per_site"][0]:
        assert f"`{key}`" in spec, f"per_site field {key} is not in the spec"
    assert evidence.SCHEMA in spec and "helix.pages.v1" in spec and "helix.watch.v1" in spec


def test_the_spec_states_the_statuses_that_are_not_an_answer():
    spec = " ".join(_read("docs", "EVIDENCE_SPEC.md").split())
    for status in (401, 403, 407, 408, 425, 429, 451, 999):
        assert str(status) in spec
        assert status in evidence.NO_ANSWER_STATUSES
    assert "5xx" in spec and all(s in evidence.NO_ANSWER_STATUSES for s in range(500, 600))


def test_the_spec_is_honest_about_what_helix_does_not_capture():
    spec = _read("docs", "EVIDENCE_SPEC.md")
    assert "Helix takes no screenshot" in spec
    assert "The collector's IP address is not recorded" in spec
    assert "not a trusted timestamp" in spec
    assert "It is not a certification" in spec


_WORDS = re.compile(
    r"(?i)\b(delve|leverag\w*|seamless\w*|robust\w*|comprehensive\w*|cutting-edge|unleash\w*|empower\w*"
    r"|streamlin\w*|elevat\w*|meticulous\w*|game-changer|tapestry)\b|it's worth noting|in today's world")


@pytest.mark.parametrize("path", DOCS, ids=lambda p: os.path.relpath(p, ROOT))
def test_public_documents_follow_the_house_style(path):
    text = open(path, encoding="utf-8").read()
    prose = re.sub(r"```.*?```", "", text, flags=re.S)          # commands and sample output
    prose = re.sub(r"`[^`\n]*`", "", prose)                      # inline code
    problems = []
    for n, line in enumerate(prose.splitlines(), 1):
        if re.search(r"[—–→]", line):
            problems.append(f"line {n}: long dash or arrow")
        if _WORDS.search(line):
            problems.append(f"line {n}: {_WORDS.search(line).group(0)!r}")
    assert problems == []


@pytest.mark.parametrize("doc,needs", [
    ("RESPONSIBLE_USE.md", ["not legal advice", "legitimate interests", "Digital Personal Data Protection Act, 2023",
                            "LEFT_OUT.md", "helix --me"]),
    ("LEFT_OUT.md", ["--left-out-token", "PBKDF2-HMAC-SHA256", "200,000", "Do not write the name itself"]),
    ("SITE_CHECK.md", ["--include-off", "3 checks in a row", "python -m osint.health check"]),
    ("LEARN.md", ["--learn", "--known", "osint/data/sites.json", "control probe"]),
])
def test_each_guide_covers_its_command(doc, needs):
    text = " ".join(_read("docs", doc).split())
    for phrase in needs:
        assert phrase in text, f"{doc} does not mention {phrase!r}"


def test_the_guides_state_the_numbers_the_code_uses():
    from osint import health, leftout
    assert f"{leftout.ROUNDS:,} rounds" in _read("docs", "LEFT_OUT.md")
    site_check = _read("docs", "SITE_CHECK.md")
    assert f"on {health.OFF_AFTER} checks in a row" in site_check
    assert f"less than {health.MIN_GAP_HOURS} hours apart" in " ".join(site_check.split())
    assert f"last {health.KEEP_RUNS} checks" in site_check
