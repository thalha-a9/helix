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


# Several profiles, several names (laptop run, Oct 2026: "torvalds" on Medium
# is Patricia Torvalds, so the first name seen was printed as the subject's).

def _prof(platform, og, confidence="high"):
    return {"platform": platform, "og_title": og, "confidence": confidence, "found": True}


def test_names_keep_their_source_and_most_shared_comes_first():
    from osint.subject import names_on_profiles
    found = [_prof("Medium", "Patricia Torvalds – Medium"),
             _prof("GitHub", "Linus Torvalds - GitHub"),
             _prof("Snapchat", "Linus Torvalds on Snapchat")]
    names = names_on_profiles(found, "torvalds")
    assert list(names) == ["Linus Torvalds", "Patricia Torvalds"]
    assert names["Linus Torvalds"] == ["GitHub", "Snapchat"]
    assert names["Patricia Torvalds"] == ["Medium"]


def test_names_ignore_unverified_profiles_and_merge_case():
    from osint.subject import names_on_profiles
    found = [_prof("A", "Jane Roe - A"), _prof("B", "JANE ROE - B"),
             _prof("C", "Someone Else - C", confidence="medium")]
    assert names_on_profiles(found, "janeroe") == {"Jane Roe": ["A", "B"]}


def test_a_tie_keeps_scan_order():
    from osint.subject import names_on_profiles
    found = [_prof("A", "Jane Roe - A"), _prof("B", "John Doe - B")]
    assert list(names_on_profiles(found, "x")) == ["Jane Roe", "John Doe"]


def test_entities_in_og_titles_are_decoded():
    """Instagram escapes its og:title (laptop recheck, Oct 2026)."""
    from osint.checker import _extract_og_tag
    html = '<meta property="og:title" content="Marco Migozzi (&#064;torvalds) &#x2022; Instagram photos and videos">'
    title = _extract_og_tag(html, "title")
    assert title == "Marco Migozzi (@torvalds) • Instagram photos and videos"
    assert real_name_from_title(title, "Instagram", "torvalds") == "Marco Migozzi"
