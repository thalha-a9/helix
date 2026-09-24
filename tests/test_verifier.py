"""False-positive engine — every purge layer needs a positive and a negative case."""

from osint.verifier import (
    run_local_verifier, _has_soft_404_content, _has_waf_content,
    _is_registration_api_url, _is_bad_redirect, _username_valid_for_platform,
)


def result(**overrides):
    base = {
        "platform": "Example", "url": "https://example.com/janeroe",
        "final_url": "https://example.com/janeroe", "found": True,
        "confidence": "medium", "source": "builtin", "og_title": "Jane Roe",
        "error": None, "_page_text": "<html>Jane Roe's profile</html>",
    }
    base.update(overrides)
    return base


# ── Layer helpers ────────────────────────────────────────────────────────────

def test_soft_404_content_detection():
    assert _has_soft_404_content("<h1>User not found</h1>")
    assert not _has_soft_404_content("<h1>Jane Roe</h1>")
    assert not _has_soft_404_content("")


def test_waf_content_detection():
    assert _has_waf_content("Just a moment... checking your browser")
    assert not _has_waf_content("<html>Jane Roe</html>")


def test_registration_api_url_detection():
    assert _is_registration_api_url("https://x.com/api/checkusername?u=janeroe")
    assert not _is_registration_api_url("https://github.com/janeroe")


def test_bad_redirect_detection():
    assert _is_bad_redirect("https://x.com/janeroe", "https://x.com/login")
    assert _is_bad_redirect("https://x.com/janeroe", "https://other.com/janeroe")
    assert not _is_bad_redirect("https://x.com/janeroe", "https://x.com/janeroe")


def test_platform_username_format_rules():
    ok, _ = _username_valid_for_platform("janeroe", "Twitter/X")
    assert ok
    # Twitter handles are max 15 chars and cannot contain dots.
    bad, reason = _username_valid_for_platform("jane.roe.is.very.long", "Twitter/X")
    assert not bad and "format rules" in reason


def test_unknown_platform_has_no_format_rule():
    ok, _ = _username_valid_for_platform("anything!", "Nonexistent Platform")
    assert ok


# ── End-to-end purging ───────────────────────────────────────────────────────

def test_genuine_profile_survives():
    results = [result()]
    results, purged = run_local_verifier(results, "janeroe")
    assert results[0]["found"] is True
    assert purged == []


def test_soft_404_is_purged():
    results = [result(_page_text="<h1>User not found</h1>")]
    results, purged = run_local_verifier(results, "janeroe")
    assert results[0]["found"] is False
    assert len(purged) == 1
    assert "heuristic_purge" in results[0]["error"]


def test_waf_page_is_purged():
    results = [result(_page_text="Just a moment... checking your browser")]
    results, purged = run_local_verifier(results, "janeroe")
    assert results[0]["found"] is False


def test_registration_api_is_purged():
    results = [result(url="https://x.com/api/checkusername?u=janeroe")]
    results, purged = run_local_verifier(results, "janeroe")
    assert results[0]["found"] is False


def test_login_redirect_is_purged():
    results = [result(final_url="https://example.com/login")]
    results, purged = run_local_verifier(results, "janeroe")
    assert results[0]["found"] is False


def test_username_violating_platform_rules_is_purged():
    results = [result(platform="Twitter/X", url="https://twitter.com/jane.roe.long.handle")]
    results, purged = run_local_verifier(results, "jane.roe.long.handle")
    assert results[0]["found"] is False


# ── Redirect handling — regressions from a live scan ─────────────────────────

import pytest


@pytest.mark.parametrize("platform,url,probe,final", [
    # API-probed: the redirect check must compare against the API URL we hit.
    ("Chess.com", "https://www.chess.com/member/torvalds",
     "https://api.chess.com/pub/player/torvalds", "https://api.chess.com/pub/player/torvalds"),
    ("Bluesky", "https://bsky.app/profile/torvalds.bsky.social",
     "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=torvalds.bsky.social",
     "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=torvalds.bsky.social"),
    # Same site, different subdomain, username kept.
    ("Gravatar", "https://en.gravatar.com/torvalds", "https://en.gravatar.com/torvalds",
     "https://gravatar.com/torvalds"),
    ("Tumblr", "https://torvalds.tumblr.com/", "https://torvalds.tumblr.com/",
     "https://www.tumblr.com/@torvalds"),
])
def test_legitimate_redirects_are_not_purged(platform, url, probe, final):
    r = result(platform=platform, url=url, probe_url=probe, final_url=final,
               og_title="", confidence="medium", _page_text='{"username":"torvalds"}')
    results, purged = run_local_verifier([r], "torvalds")
    assert results[0]["found"] is True, purged


@pytest.mark.parametrize("final", [
    "https://www.tumblr.com/login",          # same site, but a login wall
    "https://www.tumblr.com/",               # same site, homepage, no username
    "https://www.tumblr.com/explore",        # same site, username dropped
    "https://evil.example/torvalds",         # different site keeping the username
])
def test_suspicious_redirects_are_still_purged(final):
    r = result(platform="Tumblr", url="https://torvalds.tumblr.com/",
               probe_url="https://torvalds.tumblr.com/", final_url=final,
               og_title="", confidence="medium", _page_text="<html>x</html>")
    results, _ = run_local_verifier([r], "torvalds")
    assert results[0]["found"] is False


def test_probe_url_recorded_by_checker():
    import asyncio
    from osint import checker
    r = {"url": "https://www.chess.com/member/x", "confidence": "low", "found": False,
         "bio_links": {}, "og_title": ""}
    asyncio.run(checker._apply(r, {"method": "status_code", "found": [200]}, "x", 200, "{}",
                               "https://api.chess.com/pub/player/x",
                               "https://api.chess.com/pub/player/x"))
    assert r["probe_url"] == "https://api.chess.com/pub/player/x"


def test_not_found_results_are_left_alone():
    results = [result(found=False, _page_text="<h1>User not found</h1>")]
    results, purged = run_local_verifier(results, "janeroe")
    assert purged == []


def test_high_confidence_needs_a_stronger_signal_to_purge():
    """og_meta-verified results use the stricter threshold."""
    results = [result(confidence="high", og_title="", _page_text="<html>ok</html>")]
    results, purged = run_local_verifier(results, "janeroe")
    assert results[0]["found"] is True


def test_purge_log_carries_platform_and_reason():
    results = [result(_page_text="<h1>User not found</h1>")]
    _, purged = run_local_verifier(results, "janeroe")
    assert purged[0]["platform"] == "Example"
    assert purged[0]["reason"]
    assert purged[0]["score"] >= 60
