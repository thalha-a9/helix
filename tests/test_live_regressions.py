"""
Detection rules rebuilt from live pages (Oct 2026). Logged out, several big
platforms answer every name with the same wall, so only positive profile
evidence counts.
"""

import pytest

from osint import checker
from osint.platforms import PLATFORMS
from osint.verifier import run_local_verifier


def _r(platform):
    return {"platform": platform, "url": "u", "category": "social", "color": "#fff",
            "found": False, "error": None, "confidence": "low", "bio_links": {}, "og_title": ""}


async def _apply(platform, username, status, body):
    r = _r(platform)
    await checker._apply(r, PLATFORMS[platform], username, status, body, "u", "u")
    return r


TIKTOK_REAL = ('<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__">{"statusCode":0,'
               '"userInfo":{"user":{"id":"1","uniqueId":"tiktok","nickname":"TikTok"},'
               '"stats":{"followerCount":96000000}}}</script>')
TIKTOK_UNKNOWN = '<script>{"statusCode":10221,"statusMsg":"user not exist"}</script> @x1x1ovwfpu1c'
IG_REAL = ('<meta property="og:title" content="Mark Zuckerberg (&#064;zuck) &#x2022; '
           'Instagram photos and videos" />')
IG_WALL = '<html><title>Instagram</title><body>Log in · zuck · Sign up</body></html>'


@pytest.mark.asyncio
async def test_tiktok_needs_the_embedded_user_record():
    assert (await _apply("TikTok", "tiktok", 200, TIKTOK_REAL))["found"] is True
    assert (await _apply("TikTok", "x1x1ovwfpu1c", 200, TIKTOK_UNKNOWN))["found"] is False
    # Another account's record on the page is not this user's
    assert (await _apply("TikTok", "tik", 200, TIKTOK_REAL))["found"] is False


@pytest.mark.asyncio
async def test_instagram_needs_the_profile_og_title():
    assert (await _apply("Instagram", "zuck", 200, IG_REAL))["found"] is True
    assert (await _apply("Instagram", "zuck", 200, IG_WALL))["found"] is False
    assert (await _apply("Instagram", "zuck", 429, IG_REAL))["found"] is False


@pytest.mark.parametrize("platform,url", [("Facebook", "https://www.facebook.com/zuck"),
                                          ("Threads", "https://www.threads.com/@zuck")])
def test_login_walled_platforms_are_never_reported(platform, url):
    r = {**_r(platform), "url": url, "final_url": url, "found": True, "confidence": "medium",
         "_page_text": "<html>zuck</html>"}
    results, purged = run_local_verifier([r], "zuck")
    assert results[0]["found"] is False and purged
