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
