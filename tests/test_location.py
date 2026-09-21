from osint import location


# ── Gazetteer resolution ─────────────────────────────────────────────────────

def test_resolves_country_names_and_cities():
    assert location.resolve_countries("Wellington, New Zealand") == {"New Zealand"}
    assert location.resolve_countries("Auckland") == {"New Zealand"}
    assert location.resolve_countries("Chennai, India") == {"India"}


def test_resolves_us_states_and_cities():
    assert location.resolve_countries("Austin, Texas") == {"United States"}
    assert location.resolve_countries("Brooklyn") == {"United States"}


def test_resolves_uppercase_iso2_codes():
    assert location.resolve_countries("Wellington, NZ") == {"New Zealand"}


def test_lowercase_in_is_not_treated_as_india():
    """'IN' is India only as a standalone code — never the English word."""
    assert "India" not in location.resolve_countries("living in the mountains")


def test_unknown_location_resolves_to_nothing():
    assert location.resolve_countries("somewhere nice") == set()
    assert location.resolve_countries("") == set()


def test_describe_subject_location():
    assert "New Zealand" in location.describe_subject_location("Wellington, NZ")
    assert "unrecognised" in location.describe_subject_location("qqqzzz")


# ── Hint extraction ──────────────────────────────────────────────────────────

def test_extracts_json_location_field():
    assert "Auckland, New Zealand" in location.extract_location_hints(
        '{"login":"x","location":"Auckland, New Zealand"}'
    )


def test_extracts_label_and_pin_and_based_in():
    assert "Berlin" in location.extract_location_hints("<p>Location: Berlin</p>")
    assert "Tokyo" in location.extract_location_hints("<span>📍 Tokyo</span>")
    assert "Lisbon" in location.extract_location_hints("<p>Based in Lisbon</p>")


def test_extracts_location_css_class():
    assert "Toronto" in location.extract_location_hints(
        '<span class="profile-location">Toronto</span>'
    )


def test_ignores_bare_country_names_in_page_chrome():
    """A country name in a footer is not a claim about the account holder."""
    html = "<footer>Available in Germany, France and Spain</footer>"
    assert location.extract_location_hints(html) == []


def test_ignores_noise_values():
    assert location.extract_location_hints('{"location":"null"}') == []
    assert location.extract_location_hints('{"location":"https://x.com"}') == []


# ── Annotation and conflict flagging ─────────────────────────────────────────

def _found(platform, page_text):
    return {"platform": platform, "url": f"https://{platform}.com/u",
            "found": True, "confidence": "high", "og_title": "",
            "_page_text": page_text}


def test_annotate_records_hints_and_countries():
    results = [_found("Strava", '{"location":"Auckland, New Zealand"}')]
    location.annotate_locations(results)
    assert results[0]["location_countries"] == ["New Zealand"]
    assert results[0]["location_hints"] == ["Auckland, New Zealand"]


def test_annotate_skips_not_found_results():
    results = [{"platform": "X", "found": False,
                "_page_text": '{"location":"Berlin"}'}]
    location.annotate_locations(results)
    assert "location_countries" not in results[0]


def test_conflict_flagged_and_confidence_downgraded():
    results = [_found("Strava", '{"location":"Auckland, New Zealand"}')]
    location.annotate_locations(results)
    conflicts = location.flag_conflicts(results, "London, United Kingdom")

    assert len(conflicts) == 1
    assert conflicts[0]["stated"] == ["New Zealand"]
    assert conflicts[0]["expected"] == ["United Kingdom"]
    assert results[0]["location_conflict"] is True
    assert results[0]["confidence"] == "medium"
    # Never purged — the investigator decides.
    assert results[0]["found"] is True


def test_matching_location_is_not_a_conflict():
    results = [_found("Strava", '{"location":"Manchester, England"}')]
    location.annotate_locations(results)
    assert location.flag_conflicts(results, "London, United Kingdom") == []
    assert not results[0].get("location_conflict")


def test_profile_without_stated_location_is_never_penalised():
    results = [_found("Strava", "<html>no location anywhere</html>")]
    location.annotate_locations(results)
    assert location.flag_conflicts(results, "London, UK") == []
    assert results[0]["confidence"] == "high"


def test_unrecognised_subject_location_disables_checking():
    results = [_found("Strava", '{"location":"Auckland, New Zealand"}')]
    location.annotate_locations(results)
    assert location.flag_conflicts(results, "qqqzzz") == []
    assert location.flag_conflicts(results, "") == []


def test_multi_country_profile_overlapping_subject_is_not_a_conflict():
    results = [_found("Strava", '{"location":"London / Auckland"}')]
    location.annotate_locations(results)
    assert location.flag_conflicts(results, "New Zealand") == []
