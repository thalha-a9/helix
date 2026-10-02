import pytest

from osint import checker


@pytest.mark.parametrize("username", ["johndoe", "john.doe", "john_doe", "a-b", "x1"])
def test_validate_username_accepts_valid(username):
    ok, msg = checker.validate_username(username)
    assert ok and msg == ""


@pytest.mark.parametrize("username,fragment", [
    ("",            "empty"),
    ("a" * 51,      "too long"),
    ("john doe",    "Invalid characters"),
    ("john/../doe", "Invalid characters"),
    ("john@doe",    "Invalid characters"),
    ("<script>",    "Invalid characters"),
])
def test_validate_username_rejects_invalid(username, fragment):
    ok, msg = checker.validate_username(username)
    assert not ok
    assert fragment.lower() in msg.lower()


@pytest.mark.parametrize("email", [
    "a@b.co", "john.doe+tag@example.com", "x_y@sub.domain.org",
])
def test_validate_email_accepts_valid(email):
    ok, _ = checker.validate_email(email)
    assert ok


@pytest.mark.parametrize("email", [
    "", "plainstring", "a@b", "@example.com", "a@.com", "a b@example.com",
])
def test_validate_email_rejects_invalid(email):
    ok, msg = checker.validate_email(email)
    assert not ok and msg


def test_extract_og_tag_property_then_content():
    html = '<meta property="og:title" content="Jane Roe">'
    assert checker._extract_og_tag(html, "title") == "Jane Roe"


def test_extract_og_tag_content_then_property():
    html = '<meta content="Jane Roe" property="og:title">'
    assert checker._extract_og_tag(html, "title") == "Jane Roe"


def test_extract_og_tag_name_attribute_and_case_insensitive():
    html = '<META NAME="OG:TITLE" CONTENT="Jane Roe">'
    assert checker._extract_og_tag(html, "title") == "Jane Roe"


def test_extract_og_tag_missing_returns_none():
    assert checker._extract_og_tag("<html></html>", "title") is None
    assert checker._extract_og_tag("", "title") is None


def test_extract_bio_links_finds_handles():
    html = '<a href="https://github.com/janeroe">gh</a> twitter.com/janeroe_'
    out = checker._extract_bio_links(html, {
        "github":  r"github\.com/([a-zA-Z0-9_\-]{1,100})",
        "twitter": r"twitter\.com/([a-zA-Z0-9_]{1,50})",
    })
    assert out == {"github": "janeroe", "twitter": "janeroe_"}


def test_extract_bio_links_ignores_markup_and_cdn_hosts():
    """Regression: the og: namespace in <html prefix> was reported as a user's website."""
    from osint.platforms import _BIO_PATTERNS_DEVELOPER
    html = ('<html prefix="og: http://ogp.me/ns#">'
            '<link rel="dns-prefetch" href="https://github.githubassets.com">'
            '<link href="https://fonts.googleapis.com/css?family=x">'
            '<a href="https://janeroe.dev">site</a></html>')
    assert checker._extract_bio_links(html, {"website": _BIO_PATTERNS_DEVELOPER["website"]}) \
        == {"website": "https://janeroe.dev"}


def test_extract_bio_links_returns_nothing_when_only_noise():
    from osint.platforms import _BIO_PATTERNS_DEVELOPER
    html = '<html prefix="og: http://ogp.me/ns#"><link href="https://schema.org/Person"></html>'
    assert checker._extract_bio_links(html, {"website": _BIO_PATTERNS_DEVELOPER["website"]}) == {}


def test_extract_bio_links_skips_missing_patterns():
    assert checker._extract_bio_links("<html></html>", {"github": r"github\.com/(\w+)"}) == {}


@pytest.mark.parametrize("n,expected", [(1, 20), (50, 20), (51, 40), (200, 40), (201, 60)])
def test_dynamic_concurrency_tiers(n, expected):
    assert checker._dynamic_concurrency(n) == expected


@pytest.mark.parametrize("url", [
    "https://x.com/api/v1/users",
    "https://x.com/check?username=bob",
    "https://x.com/wp-json/wporg/v1/username",
])
def test_is_api_url_detects_api_endpoints(url):
    assert checker._is_api_url(url)


def test_is_api_url_ignores_plain_profiles():
    assert not checker._is_api_url("https://github.com/janeroe")


@pytest.mark.parametrize("body", [
    "[]", "{}", '{"users":[]}', '{"available": true}',
    '{"exists":false}', '{"valid":false}', '{"error":404}',
])
def test_api_says_not_found(body):
    assert checker._api_says_not_found(body)


def test_api_says_not_found_ignores_real_payload():
    assert not checker._api_says_not_found('{"id": 42, "username": "janeroe"}')


def test_waf_page_detection():
    assert checker._is_waf_page("<html><title>Just a moment...</title>")
    assert not checker._is_waf_page("<html><title>Jane Roe</title>")


def test_dead_site_detection():
    assert checker._is_dead_site("<p>This domain is parked</p>")
    assert not checker._is_dead_site("<p>Jane Roe's profile</p>")


@pytest.mark.parametrize("value", [
    "https://pbs.twimg.com/profile_images/1258799683998121984/eqlAB8Uz_400x400.jpg",  # live X page
    "https://example.com/banner.png?v=2", "https://scontent.cdninstagram.com/a/b",
    "https://static.example.com/app.css",
])
def test_media_files_are_never_bio_links(value):
    from osint.checker import _is_bio_noise
    assert _is_bio_noise(value)


@pytest.mark.parametrize("value", ["https://krisnova.net", "https://jack.blog/about", "github.com/torvalds"])
def test_real_sites_are_kept_as_bio_links(value):
    from osint.checker import _is_bio_noise
    assert not _is_bio_noise(value)


def test_self_links_are_dropped():
    from osint.checker import _drop_self_links
    # Live Dev.to / Linktree pages for "jack" (Oct 2026)
    assert _drop_self_links({"devto": "jack", "website": "https://dev.to/jack"},
                            "https://dev.to/jack", "Dev.to") == {}
    assert _drop_self_links({"website": "https://linktr.ee/jack"},
                            "https://linktr.ee/jack", "Linktree") == {}
    assert _drop_self_links({"github": "jack", "website": "https://jack.blog"},
                            "https://dev.to/jack", "Dev.to") == {"github": "jack",
                                                                  "website": "https://jack.blog"}


def test_platform_onion_mirror_is_not_a_bio_link():
    from osint.checker import _is_bio_noise
    assert _is_bio_noise("https://twitter3e4tixl4xyajtrzo62zg5vztmjuricljdp2c5kshju4avyoid.onion")


def test_shortener_root_is_noise_but_short_links_are_not():
    from osint.checker import _is_bio_noise
    assert _is_bio_noise("https://t.co")                      # in every logged-out X page
    assert not _is_bio_noise("https://t.co/ZdBx5WABYx")       # a user's actual link


def test_pivot_never_treats_a_website_as_an_alias():
    from osint.pivot import _extract_aliases
    assert _extract_aliases({"website": "https://t.co", "twitter": "maxtaco",
                             "github": "https://evil/x"}) == {"maxtaco"}


@pytest.mark.asyncio
async def test_keybase_api_answer_and_proofs():
    from osint import checker
    from osint.platforms import PLATFORMS
    # Live API shapes (Oct 2026)
    real = ('{"status":{"code":0,"name":"OK"},"them":[{"basics":{"username":"max"},'
            '"proofs_summary":{"all":[{"proof_type":"twitter","nametag":"maxtaco",'
            '"service_url":"https://twitter.com/maxtaco"},{"proof_type":"github","nametag":"maxtaco",'
            '"service_url":"https://github.com/maxtaco"}]}}]}')
    gone = '{"status":{"code":0,"name":"OK"},"them":[null]}'
    for body, want in ((real, True), (gone, False)):
        r = {"platform": "Keybase", "url": "https://keybase.io/max", "category": "other",
             "color": "#fff", "found": False, "error": None, "confidence": "low",
             "bio_links": {}, "og_title": ""}
        await checker._apply(r, PLATFORMS["Keybase"], "max", 200, body, "u", "u")
        assert r["found"] is want
    assert r["found"] is False
    r = {"platform": "Keybase", "url": "https://keybase.io/max", "category": "other",
         "color": "#fff", "found": False, "error": None, "confidence": "low", "bio_links": {}, "og_title": ""}
    await checker._apply(r, PLATFORMS["Keybase"], "max", 200, real, "u", "u")
    assert r["bio_links"] == {"twitter": "maxtaco", "github": "maxtaco"}


def test_site_paths_are_not_handles():
    """Live Linktree page: youtube.com/channel/UC… was read as the handle "channel"."""
    from osint.checker import _extract_bio_links
    from osint.platforms import PLATFORMS
    html = ('<a href="https://www.youtube.com/channel/UCabc123">yt</a>'
            '<a href="https://twitter.com/intent/tweet?x=1">share</a>'
            '<a href="https://github.com/features">gh</a>'
            '<a href="https://www.youtube.com/@realjane">yt2</a>'
            '<a href="https://github.com/janeroe">gh2</a>')
    links = _extract_bio_links(html, PLATFORMS["Linktree"]["bio_patterns"])
    assert links.get("youtube") == "realjane" and links.get("github") == "janeroe"
