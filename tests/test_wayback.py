"""Wayback: true first/last capture, clues only from the archived bio."""

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
