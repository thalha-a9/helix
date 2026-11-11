"""
Maigret engines: two thirds of Maigret's entries name an engine (XenForo,
Discourse, uCoz, MediaWiki, Gitea ...) and give no address of their own.

Found by the daily site check on 10 Nov 2026: 4,398 Maigret sites answered a
made-up name but never found the account Maigret lists for them. Helix did
not read engines and asked "https://site/{username}", which is 404 for every
name. Those sites counted as answered and could not find anyone.
"""

import pytest

import helix_osint.checker as ck
from helix_osint.adapters.maigret_adapter import _translate
from helix_osint.platform_schema import fallback_defs, problems

# Engines as soxoj/maigret data.json defined them on 10 Nov 2026 (shortened).
ENGINES = {
    "XenForo": {"site": {
        "ignore403": True, "checkType": "message",
        "absenceStrs": ["The requested page could not be found.",
                        "The specified member cannot be found. Please enter a member"],
        "presenseStrs": ["memberHeader"],
        "url": "{urlMain}{urlSubpath}/members/?username={username}"}},
    "Discourse": {"site": {
        "presenseStrs": ['<meta name="generator" content="Discourse'],
        "absenceStrs": ["Oops! That page doesn’t exist or is private.", "wrap not-found-container"],
        "checkType": "message", "url": "{urlMain}/u/{username}/summary"}},
    "DiscourseJson": {"site": {"checkType": "status_code", "url": "{urlMain}/u/{username}",
                               "urlProbe": "{urlMain}/u/{username}.json"}},
    "uCoz": {"site": {"absenceStrs": ["<title>HTTP 404", "Пользователь не найден"],
                      "checkType": "message", "url": "{urlMain}/index/8-0-{username}"}},
    "MediaWikiJson": {"site": {
        "url": "{urlMain}{urlSubpath}/User:{username}",
        "urlProbe": "{urlMain}/api.php?action=query&list=users&ususers={username}&format=json",
        "checkType": "message", "presenseStrs": ['"userid":'],
        "absenceStrs": ['"missing":', '"invalid":']}},
    "GitLab": {"site": {"url": "{urlMain}/{username}", "checkType": "message",
                        "presenseStrs": ["js-user-profile-actions"]}},
    "Gitea": {"site": {"url": "{urlMain}/{username}", "checkType": "status_code"}},
    "Mastodon": {"site": {"checkType": "status_code", "url": "{urlMain}/@{username}",
                          "urlProbe": "{urlMain}/api/v1/accounts/lookup?acct={username}"}},
    "Lemmy": {"site": {"url": "{urlMain}/u/{username}", "checkType": "status_code",
                       "urlProbe": "{urlMain}/api/v3/user?username={username}"}},
    "engine404": {"site": {"checkType": "status_code"}},
}


def entry(engine, main="https://forum.example", **extra):
    return {"tags": ["forum"], "urlMain": main, "usernameClaimed": "Pyure",
            "usernameUnclaimed": "noonewouldeverusethis7", "engine": engine, **extra}


def test_a_xenforo_forum_is_asked_at_its_member_lookup():
    pdef = _translate("forum.feed-the-beast.com", entry("XenForo"), ENGINES)
    assert pdef["url"] == "https://forum.example/members/?username={username}"
    assert pdef["method"] == "text_not_present"
    assert pdef["not_found_texts"] == ENGINES["XenForo"]["site"]["absenceStrs"]
    assert pdef["known"] == "Pyure" and pdef["source"] == "maigret"
    assert problems(pdef) == []


def test_the_subpath_and_a_trailing_slash_are_joined_cleanly():
    pdef = _translate("X", entry("XenForo", main="https://example.org/", urlSubpath="/forum"), ENGINES)
    assert pdef["url"] == "https://example.org/forum/members/?username={username}"


def test_an_api_probe_is_asked_and_the_profile_page_is_shown():
    pdef = _translate("meta.example", entry("DiscourseJson"), ENGINES)
    assert pdef["url"] == "https://forum.example/u/{username}"
    assert pdef["check_url"] == "https://forum.example/u/{username}.json"
    assert pdef["method"] == "status_code" and pdef["found"] == [200]
    wiki = _translate("wiki.example", entry("MediaWikiJson"), ENGINES)
    assert wiki["url"] == "https://forum.example/User:{username}"
    assert wiki["check_url"].startswith("https://forum.example/api.php?action=query")
    assert wiki["method"] == "text_not_present" and wiki["not_found_texts"] == ['"missing":', '"invalid":']


def test_an_entrys_own_fields_win_over_its_engine():
    pdef = _translate("X", entry("Discourse", absenceStrs=["No such member"],
                                 url="{urlMain}/people/{username}"), ENGINES)
    assert pdef["url"] == "https://forum.example/people/{username}"
    assert pdef["not_found_texts"] == ["No such member"]


def test_an_engine_that_only_fixes_the_check_type_keeps_the_entrys_address():
    pdef = _translate("X", entry("engine404", url="https://x.example/user/{username}"), ENGINES)
    assert pdef["url"] == "https://x.example/user/{username}" and pdef["method"] == "status_code"


@pytest.mark.parametrize("info", [
    entry("NoSuchEngine"),                                   # an engine the database does not define
    {"urlMain": "https://x.example", "usernameClaimed": "a"},   # no address pattern at all
    entry("engine404"),                                      # engine without one either
    entry("XenForo", requestMethod="POST"),                  # cannot be asked with a GET
    {"url": "https://x.example/{username}", "requestMethod": "POST"},
])
def test_no_address_is_ever_guessed(info):
    assert _translate("X", info, ENGINES) is None


def test_a_presence_only_rule_also_needs_the_page_to_name_the_user():
    pdef = _translate("gitlab.example", entry("GitLab"), ENGINES)
    assert pdef["method"] == "text_present" and pdef["found_texts"] == ["js-user-profile-actions"]
    assert pdef["name_in_page"] is True and problems(pdef) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("page,found", [
    ('<div class="js-user-profile-actions"></div><h1>janeroe</h1>', True),
    ('<div class="js-user-profile-actions"></div><h1>somebody else</h1>', False),
    ('<h1>janeroe</h1> sign in to continue', False),
])
async def test_presence_rule_on_a_page(page, found):
    pdef = _translate("gitlab.example", entry("GitLab"), ENGINES)
    result = {"platform": "x", "url": "", "found": False, "error": None}
    await ck._apply(result, pdef, "janeroe", 200, page, pdef["url"])
    assert result["found"] is found


@pytest.mark.asyncio
async def test_any_one_of_several_found_texts_is_enough():
    pdef = {"method": "text_present", "found_texts": ["udtlb", "rankimg"], "found_text": "udtlb"}
    for page, found in (("<img name='rankimg'>", True), ("<b>udtlb</b>", True), ("nothing", False)):
        result = {"platform": "x", "url": "", "found": False, "error": None}
        await ck._apply(result, pdef, "janeroe", 200, page, "")
        assert result["found"] is found


@pytest.mark.parametrize("engine,software", [("Mastodon", "mastodon"), ("Lemmy", "lemmy")])
def test_fediverse_engines_get_helix_own_rule_with_webfinger(engine, software):
    from helix_osint.adapters.fediverse_adapter import platform_for
    pdef = _translate("social.example", entry(engine, main="https://social.example"), ENGINES)
    own = platform_for("social.example", software)
    assert pdef["check_url"] == own["check_url"] and pdef["found_text"] == own["found_text"]
    assert pdef["source"] == "maigret" and pdef["known"] == "Pyure"
    assert len(fallback_defs(pdef)) == 1 and "webfinger" in fallback_defs(pdef)[0]["check_url"]
    assert problems(pdef) == []


def test_request_headers_and_tls_marks_are_carried():
    info = {"url": "https://x.example/api/{username}", "checkType": "status_code",
            "headers": {"x-ig-app-id": "936619743392459"}, "protection": ["tls_fingerprint"]}
    pdef = _translate("X", info, ENGINES)
    assert pdef["headers"] == {"x-ig-app-id": "936619743392459"} and pdef["tls_impersonate"] is True
    assert problems(pdef) == []
    bad = _translate("X", {**info, "headers": {"X-A": "1\r\nHost: evil.example"}}, ENGINES)
    assert "headers" not in bad
    assert problems({**pdef, "headers": {"X-A": "1\r\nHost: evil.example"}}) == [
        "headers is not a map of header names to single-line values"]


def test_a_sites_own_headers_replace_the_browser_ones_of_the_same_name():
    h = ck._headers({"headers": {"user-agent": "curl/8.6.0", "Accept": "*/*", "X-App": "1"}})
    assert h["user-agent"] == "curl/8.6.0" and "User-Agent" not in h
    assert h["Accept"] == "*/*" and h["X-App"] == "1" and "Accept-Language" in h
    assert "X-App" not in ck._headers() and "X-App" not in ck._headers({})


def test_entries_without_an_engine_translate_as_before():
    plain = {"url": "https://x.test/{username}", "absenceStrs": "Not found", "usernameClaimed": "adam"}
    assert _translate("X", plain) == _translate("X", plain, ENGINES)
    assert _translate("X", plain)["method"] == "text_not_present"
    status = _translate("Y", {"url": "https://y.test/u/{username}", "checkType": "status_code"})
    assert status["method"] == "status_code" and status["found"] == [200]
