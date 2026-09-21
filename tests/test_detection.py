"""Detection-method correctness — one positive and one negative per method."""

import pytest

from osint import checker

pytestmark = pytest.mark.asyncio


async def apply(base_result, platform, status, text, final_url="", username="janeroe"):
    await checker._apply(base_result, platform, username, status, text,
                         final_url or platform["url"], platform["url"])
    return base_result


# ── status_code ──────────────────────────────────────────────────────────────

async def test_status_code_found(base_result):
    plat = {"url": "https://x.com/u", "method": "status_code", "found": [200]}
    r = await apply(base_result, plat, 200, "<html>profile</html>")
    assert r["found"] and r["confidence"] == "medium"


async def test_status_code_not_found(base_result):
    plat = {"url": "https://x.com/u", "method": "status_code", "found": [200]}
    r = await apply(base_result, plat, 404, "")
    assert not r["found"]


async def test_status_code_soft404_body_overrides_when_flagged(base_result):
    plat = {"url": "https://x.com/u", "method": "status_code",
            "found": [200], "wmn_soft404_risk": True}
    r = await apply(base_result, plat, 200, "<h1>User not found</h1>")
    assert not r["found"]
    assert "soft404" in r["error"]


# ── text_not_present ─────────────────────────────────────────────────────────

async def test_text_not_present_found(base_result):
    plat = {"url": "https://x.com/u", "method": "text_not_present",
            "not_found_text": "This account doesn't exist"}
    r = await apply(base_result, plat, 200, "<html>Jane Roe's profile</html>")
    assert r["found"]


async def test_text_not_present_absent_when_marker_present(base_result):
    plat = {"url": "https://x.com/u", "method": "text_not_present",
            "not_found_text": "This account doesn't exist"}
    r = await apply(base_result, plat, 200, "<html>This account doesn't exist</html>")
    assert not r["found"]


async def test_text_not_present_requires_200(base_result):
    plat = {"url": "https://x.com/u", "method": "text_not_present",
            "not_found_text": "nope"}
    r = await apply(base_result, plat, 500, "<html>server error</html>")
    assert not r["found"]


# ── text_present ─────────────────────────────────────────────────────────────

async def test_text_present_found_with_username_substitution(base_result):
    plat = {"url": "https://x.com/u", "method": "text_present",
            "found_text": "@{username}"}
    r = await apply(base_result, plat, 200, "<html>Welcome @janeroe</html>")
    assert r["found"]


async def test_text_present_not_found(base_result):
    plat = {"url": "https://x.com/u", "method": "text_present",
            "found_text": "@{username}"}
    r = await apply(base_result, plat, 200, "<html>Nobody here</html>")
    assert not r["found"]


# ── response_url ─────────────────────────────────────────────────────────────

async def test_response_url_found_when_not_redirected_to_error(base_result):
    plat = {"url": "https://x.com/u", "method": "response_url",
            "error_url": "https://x.com/404"}
    r = await apply(base_result, plat, 200, "<html>ok</html>",
                    final_url="https://x.com/u")
    assert r["found"]


async def test_response_url_absent_when_redirected_to_error(base_result):
    plat = {"url": "https://x.com/u", "method": "response_url",
            "error_url": "https://x.com/404"}
    r = await apply(base_result, plat, 200, "<html>gone</html>",
                    final_url="https://x.com/404")
    assert not r["found"]


# ── og_meta ──────────────────────────────────────────────────────────────────

async def test_og_meta_found_via_og_not_found_list(base_result, profile_html):
    plat = {"url": "https://x.com/u", "method": "og_meta",
            "og_not_found": ["Page not found"]}
    r = await apply(base_result, plat, 200, profile_html)
    assert r["found"] and r["confidence"] == "high"
    assert r["og_title"] == "Jane Roe (@janeroe)"


async def test_og_meta_absent_when_not_found_marker_in_title(base_result):
    plat = {"url": "https://x.com/u", "method": "og_meta",
            "og_not_found": ["Page not found"]}
    html = '<meta property="og:title" content="Page not found">'
    r = await apply(base_result, plat, 200, html)
    assert not r["found"]


async def test_og_meta_absent_when_no_og_title_at_all(base_result):
    """A page with no og:title cannot confirm a profile."""
    plat = {"url": "https://x.com/u", "method": "og_meta",
            "og_not_found": ["Page not found"]}
    r = await apply(base_result, plat, 200, "<html><body>nothing</body></html>")
    assert not r["found"]


async def test_og_meta_found_via_og_found_list(base_result, profile_html):
    plat = {"url": "https://x.com/u", "method": "og_meta",
            "og_found": ["@{username}"]}
    r = await apply(base_result, plat, 200, profile_html)
    assert r["found"]


async def test_og_meta_non_200_is_never_found(base_result, profile_html):
    """Regression guard for the always-match false positive in issue #9."""
    plat = {"url": "https://x.com/u", "method": "og_meta",
            "og_not_found": ["Page not found"]}
    r = await apply(base_result, plat, 404, profile_html)
    assert not r["found"]


# ── Cross-cutting behaviour ──────────────────────────────────────────────────

async def test_waf_page_short_circuits_every_method(base_result):
    plat = {"url": "https://x.com/u", "method": "status_code", "found": [200]}
    r = await apply(base_result, plat, 200,
                    "<html><title>Just a moment...</title>Checking your browser</html>")
    assert not r["found"]
    assert "waf_blocked" in r["error"]


async def test_avatar_url_extracted_on_found(base_result, profile_html):
    plat = {"url": "https://x.com/u", "method": "og_meta", "og_not_found": ["nope"]}
    r = await apply(base_result, plat, 200, profile_html)
    assert r["avatar_url"] == "https://cdn.example.com/a.jpg"


async def test_bio_links_extracted_only_when_enabled(base_result, profile_html):
    plat = {"url": "https://x.com/u", "method": "og_meta", "og_not_found": ["nope"],
            "bio_extract": True,
            "bio_patterns": {"github": r"github\.com/([a-zA-Z0-9_\-]{1,100})"}}
    r = await apply(base_result, plat, 200, profile_html)
    assert r["bio_links"] == {"github": "janeroe"}


async def test_page_text_retained_for_verifier(base_result, profile_html):
    plat = {"url": "https://x.com/u", "method": "og_meta", "og_not_found": ["nope"]}
    r = await apply(base_result, plat, 200, profile_html)
    assert r["_page_text"].startswith("<html>")
