import pytest

from osint.platform_schema import filter_valid, problems
from osint.platforms import PLATFORMS


def good(**kw):
    d = {"url": "https://x.example/{username}", "method": "text_not_present",
         "not_found_text": "not found", "category": "social", "color": "#fff"}
    d.update(kw)
    return d


def test_sound_definition_passes():
    assert problems(good()) == []


@pytest.mark.parametrize("pdef,fragment", [
    (good(url="{username}.com"), "not http(s)"),                          # Maigret domain check
    (good(url="{urlMain}forum/u/{username}"), "not http(s)"),             # Rutracker
    (good(url="https://x.example/{urlSubpath}/{username}"), "unfilled placeholder"),
    (good(url="https://x.example/profile"), "no {username}"),
    (good(url="https://x.example/{username} "), "whitespace"),
    (good(check_url="https://api.example/{id}"), "check_url"),
    (good(method="magic"), "unknown method"),
    (good(not_found_text=""), "without not_found_text"),
    (good(method="text_present", found_text=""), "matches every page"),
    (good(method="text_present", found_text="   "), "matches every page"),
    (good(method="og_meta", og_not_found=[""]), "matches every page"),
    (good(method="og_meta"), "matches every page"),
    (good(method="response_url"), "without error_url"),
    (good(method="status_code", found=[]), "bad 'found'"),
    (good(method="status_code", found=["200"]), "bad 'found'"),
    ("not-a-dict", "not a dict"),
])
def test_unusable_definitions_are_rejected(pdef, fragment):
    assert any(fragment in p for p in problems(pdef)), problems(pdef)


def test_filter_valid_splits_and_explains():
    usable, unusable = filter_valid({"Ok": good(), "Domain": good(url="{username}.pro")})
    assert list(usable) == ["Ok"]
    assert "Domain" in unusable and unusable["Domain"]


def test_filter_valid_handles_empty_and_none():
    assert filter_valid({}) == ({}, {})
    assert filter_valid(None) == ({}, {})


@pytest.mark.parametrize("name,pdef", list(PLATFORMS.items()), ids=list(PLATFORMS))
def test_every_builtin_platform_passes_the_same_rules(name, pdef):
    assert problems(pdef) == []
