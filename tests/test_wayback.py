"""Wayback: true first/last capture, clues only from the archived bio."""

import asyncio

import pytest

from osint.modules import wayback


def test_parse_cdx_first_last_and_months():
    data = [["timestamp"], ["20150301000000"], ["20180704120000"], ["20240102000000"]]
    h = wayback.parse_cdx(data, "https://x.com/jack")
    assert (h["first_seen"], h["last_seen"], h["months"]) == ("2015-03-01", "2024-01-02", 3)
    assert h["earliest_url"] == "https://web.archive.org/web/20150301000000/https://x.com/jack"


@pytest.mark.parametrize("data", [[], [["timestamp"]], None, {"error": 1}])
def test_parse_cdx_empty(data):
    assert wayback.parse_cdx(data, "u") is None


def test_clues_come_from_the_bio_not_page_source():
    page_css = "@media screen { } @import url(x.css); contact support@twitter.com"
    assert wayback.bio_clues("Jane Roe", "Photographer") == []
    clues = wayback.bio_clues("Jane Roe (@janeroe)", "Now @jroe_photo — jane.old@mail.com", "janeroe")
    assert clues == ["email: jane.old@mail.com", "handle: @jroe_photo"]
    # whatever is in the surrounding page is never read
    assert "media" not in " ".join(wayback.bio_clues("", "", "x")) and page_css


def test_css_at_rules_are_never_handles():
    assert wayback.bio_clues("", "@media @import @font-face @keyframes", "x") == []


# Coverage (laptop run, Oct 2026: 4 of 19 torvalds profiles were looked up)

def test_rows_keep_the_archived_address():
    data = [["timestamp", "original"], ["20190101000000", "https://twitter.com/jack"]]
    h = wayback.history(wayback._rows(data, "https://x.com/jack"), "https://x.com/jack")
    assert h["url"] == "https://x.com/jack"
    assert h["earliest_url"] == "https://web.archive.org/web/20190101000000/https://twitter.com/jack"


def test_captures_from_every_variant_are_merged():
    rows = [("20190105000000", "https://twitter.com/jack"),
            ("20190120000000", "https://twitter.com/jack/"),      # same month: counted once
            ("20240301000000", "https://x.com/jack")]
    h = wayback.history(rows, "https://x.com/jack")
    assert (h["first_seen"], h["last_seen"], h["months"]) == ("2019-01-05", "2024-03-01", 2)
    assert h["latest_url"].endswith("/https://x.com/jack")


@pytest.mark.parametrize("url,want", [
    ("https://x.com/jack", ["https://x.com/jack", "https://x.com/jack/", "https://twitter.com/jack"]),
    ("https://www.instagram.com/jack/", ["https://www.instagram.com/jack/", "https://www.instagram.com/jack"]),
    ("https://www.roblox.com/user.aspx?username=jack", ["https://www.roblox.com/user.aspx?username=jack"]),
])
def test_url_variants(url, want):
    assert wayback.url_variants(url) == want


def test_every_category_is_looked_up_priority_first():
    found = [{"platform": f"G{i}", "url": f"https://g{i}.example/u", "found": True, "category": "gaming"}
             for i in range(30)]
    found.insert(5, {"platform": "Social", "url": "https://s.example/u", "found": True, "category": "social"})
    picked = wayback.profiles_to_check(found)
    assert len(picked) == wayback.LIMIT
    assert picked[0]["platform"] == "Social"
    assert picked[1]["platform"] == "G0"                    # then scan order
    assert all(r["category"] == "gaming" for r in picked[1:])


@pytest.mark.asyncio
async def test_lookup_tries_old_domain_and_reports_only_total_failure(monkeypatch):
    asked = []

    async def fake_cdx(session, url):
        asked.append(url)
        if "twitter.com" in url:
            return [("20200101000000", url)], ""
        if url.endswith("/"):
            return None, "HTTP 403"
        return [], ""

    async def no_html(session, u):
        return ""
    monkeypatch.setattr(wayback, "_cdx", fake_cdx)
    monkeypatch.setattr(wayback, "_archived_html", no_html)
    real_sleep = asyncio.sleep
    monkeypatch.setattr(wayback.asyncio, "sleep", lambda s: real_sleep(0))
    out = await wayback.check_profiles(
        [{"platform": "Twitter/X", "url": "https://x.com/jack", "found": True, "category": "social"}], "jack")
    assert asked == ["https://x.com/jack", "https://x.com/jack/", "https://twitter.com/jack"]
    assert out["Twitter/X"]["first_seen"] == "2020-01-01" and "error" not in out["Twitter/X"]
