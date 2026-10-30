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


# search pages are mentions, not accounts

import pytest as _pytest
from osint import platform_schema as _ps


@_pytest.mark.parametrize("url", [
    "https://sepiasearch.org/api/v1/search/video-channels?search=%22{username}%22&start=0",
    "https://scholar.google.com/scholar?hl=en&as_sdt=0%2C5&q={username}&btnG=",
    "https://commons.datacite.org/?query=creators.name:{username}",
    "http://forum.example/search.php?action=search&keywords=&author={username}",
    "https://community.adobe.com/t5/forums/searchpage/tab/user?q={username}",
    "https://explore.openaire.eu/search/find?keyword={username}",
])
def test_search_endpoints_are_not_scanned(url):
    pdef = {"url": url, "method": "status_code", "found": [200], "category": "other", "color": "#fff"}
    assert _ps.SEARCH_PROBLEM in _ps.problems(pdef)


@_pytest.mark.parametrize("url", [
    "https://github.com/{username}", "https://www.reddit.com/user/{username}/about.json",
    "https://gitlab.com/api/v4/users?username={username}", "https://site.example/profile?id={username}",
    "https://researchers.example/{username}",
])
def test_profile_urls_are_not_mistaken_for_search(url):
    pdef = {"url": url, "method": "status_code", "found": [200], "category": "other", "color": "#fff"}
    assert _ps.SEARCH_PROBLEM not in _ps.problems(pdef)


def test_no_builtin_platform_is_a_search_page():
    from osint.platforms import PLATFORMS
    assert [n for n, p in PLATFORMS.items()
            if _ps.is_search_url(p.get("check_url") or p.get("url"))] == []


@_pytest.mark.parametrize("url,ok", [
    ("https://{username}.tumblr.com", True),
    ("https://{username}.github.io/", True),
    ("https://www.animerpgs.com{username}", False),       # seen in a live database
    ("https://{username}.com", False),
    ("https://{username}", False),
    ("https://site{username}.example.com/", False),
    ("https://example.com/{username}", True),
])
def test_username_may_only_be_a_leading_subdomain(url, ok):
    pdef = {"url": url, "method": "status_code", "found": [200], "category": "other", "color": "#fff"}
    bad = any("inside the host" in p for p in _ps.problems(pdef))
    assert bad is (not ok)
