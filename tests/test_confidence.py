import itertools

import pytest

from osint.confidence import score_identity, HIGH, MEDIUM, LOW


def profile(platform, **extra):
    base = {"platform": platform, "found": True, "confidence": "high",
            "og_title": "", "bio_links": {}}
    base.update(extra)
    return base


def grade_of(results, platform):
    return next(r for r in results if r["platform"] == platform)["identity_confidence"]


def test_username_alone_is_low():
    results = [profile("GitHub")]
    counts = score_identity(results, "janeroe")
    assert grade_of(results, "GitHub") == LOW
    assert results[0]["selectors"] == ["username"]
    assert counts == {HIGH: 0, MEDIUM: 0, LOW: 1}


def test_not_found_results_are_not_scored():
    results = [profile("GitHub", found=False)]
    score_identity(results, "janeroe")
    assert "identity_confidence" not in results[0]


def test_avatar_match_makes_both_profiles_high():
    results = [profile("GitHub"), profile("Twitter/X")]
    score_identity(results, "janeroe", phash_matches=[
        {"platform_a": "GitHub", "platform_b": "Twitter/X",
         "match_type": "exact", "confidence": 1.0}])
    assert grade_of(results, "GitHub") == HIGH
    assert grade_of(results, "Twitter/X") == HIGH
    assert "same avatar as Twitter/X" in results[0]["evidence"]


def test_bio_cross_link_counts_in_both_directions():
    results = [profile("GitHub", bio_links={"twitter": "janeroe"}), profile("Twitter/X")]
    score_identity(results, "janeroe")
    assert "cross_link" in results[0]["selectors"]
    assert "cross_link" in results[1]["selectors"]
    assert grade_of(results, "GitHub") == HIGH


def test_cross_link_to_a_different_handle_does_not_count():
    results = [profile("GitHub", bio_links={"twitter": "someoneelse"}), profile("Twitter/X")]
    score_identity(results, "janeroe")
    assert "cross_link" not in results[0]["selectors"]


def test_website_bio_link_is_never_a_cross_link():
    results = [profile("GitHub", bio_links={"website": "janeroe"}), profile("Medium")]
    score_identity(results, "janeroe")
    assert results[0]["selectors"] == ["username"]


def test_email_confirmation_is_a_strong_selector():
    results = [profile("Spotify")]
    score_identity(results, "janeroe",
                   email_results=[{"platform": "spotify", "found": True}])
    assert results[0]["selectors"] == ["username", "email"]
    assert grade_of(results, "Spotify") == HIGH


def test_email_result_that_was_not_found_is_ignored():
    results = [profile("Spotify")]
    score_identity(results, "janeroe",
                   email_results=[{"platform": "spotify", "found": False}])
    assert grade_of(results, "Spotify") == LOW


def test_real_name_from_another_profile_is_medium():
    results = [profile("GitHub", og_title="Jane Roe"), profile("Medium", og_title="Jane Roe – Medium")]
    score_identity(results, "janeroe", real_name="Jane Roe", real_name_source="GitHub")
    assert grade_of(results, "Medium") == MEDIUM


def test_real_name_source_cannot_vouch_for_itself():
    results = [profile("GitHub", og_title="Jane Roe")]
    score_identity(results, "janeroe", real_name="Jane Roe", real_name_source="GitHub")
    assert grade_of(results, "GitHub") == LOW


def test_agreeing_location_is_a_selector():
    results = [profile("Strava", location_countries=["New Zealand"])]
    score_identity(results, "janeroe", subject_countries=["New Zealand"])
    assert results[0]["selectors"] == ["username", "location"]
    assert grade_of(results, "Strava") == MEDIUM


def test_three_weak_selectors_make_high():
    results = [profile("GitHub", og_title="Jane Roe"),
               profile("Medium", og_title="Jane Roe", location_countries=["New Zealand"])]
    score_identity(results, "janeroe", real_name="Jane Roe", real_name_source="GitHub",
                   subject_countries=["New Zealand"])
    assert grade_of(results, "Medium") == HIGH


def test_location_conflict_caps_at_low_even_with_strong_evidence():
    results = [profile("GitHub", location_conflict=True,
                       location_note="profile states New Zealand"),
               profile("Twitter/X")]
    score_identity(results, "janeroe", phash_matches=[
        {"platform_a": "GitHub", "platform_b": "Twitter/X"}])
    assert grade_of(results, "GitHub") == LOW
    assert any("capped" in e for e in results[0]["evidence"])


def test_status_code_only_detection_caps_at_medium():
    results = [profile("Forum", confidence="low"), profile("GitHub")]
    score_identity(results, "janeroe", phash_matches=[
        {"platform_a": "Forum", "platform_b": "GitHub"}])
    assert grade_of(results, "Forum") == MEDIUM
    assert grade_of(results, "GitHub") == HIGH


@pytest.mark.parametrize("selector", ["avatar", "cross_link", "email", "real_name", "location"])
def test_no_single_non_username_selector_alone_reaches_high_without_username(selector):
    """Every finding has the username selector; only it plus a second can climb."""
    from osint.confidence import _grade
    assert _grade([selector], "high", False) == LOW


def test_single_selector_is_never_high_exhaustively():
    from osint.confidence import _grade
    for sel, det, conflict in itertools.product(
            ["username", "avatar", "cross_link", "email", "real_name", "location"],
            ["high", "medium", "low"], [True, False]):
        assert _grade([sel], det, conflict) != HIGH


def test_counts_cover_every_found_profile():
    results = [profile("A"), profile("B"), profile("C", found=False)]
    counts = score_identity(results, "janeroe")
    assert sum(counts.values()) == 2
