"""Display-name extraction from og:title (feeds email permutation and dark-web terms)."""

import pytest

from osint.subject import real_name_from_title


@pytest.mark.parametrize("title,platform,user,want", [
    # Live titles from real scans (Oct 2026)
    ("HackerOne profile - jack", "HackerOne", "jack", None),       # was reported as a name
    ("Jack Brown · GitLab", "GitLab", "jack", "Jack Brown"),
    ("Linus Torvalds on Snapchat", "Snapchat", "torvalds", "Linus Torvalds"),
    ("Jack Williams — DEV Community Profile", "Dev.to", "jack", "Jack Williams"),
    ("jack - Chess Profile", "Chess.com", "jack", None),
    ("Torvalds (1424)", "Lichess", "torvalds", None),
    ("Torvalds's Profile", "Roblox", "torvalds", None),
    ("Nicolas | Substack", "Substack", "torvalds", None),
    ("Steam Community :: NaraKa", "Steam", "torvalds", None),
    ("Log in or sign up", "Facebook", "jack", None),
    ("jack's Applets - IFTTT", "IFTTT", "jack", None),
    # Formats the old extractor handled
    ("Jane Roe (@janeroe) • Instagram", "Instagram", "janeroe", "Jane Roe"),
    ("Mohammad Aqib | Dribbble", "Dribbble", "aqib", "Mohammad Aqib"),
    ("José García-López", "X", "jgl", "José García-López"),
    ("", "X", "jack", None),
])
def test_real_name_from_title(title, platform, user, want):
    assert real_name_from_title(title, platform, user) == want
