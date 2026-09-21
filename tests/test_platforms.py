"""
Schema validation for platform definitions.

A malformed definition is the cheapest way to ship an always-match false
positive: an og_meta entry with a typo'd og_not_found key reports every
username as found. These tests are the guard for that class of bug.
"""

import re

import pytest

from osint.platforms import PLATFORMS, CATEGORY_META

VALID_METHODS = {"og_meta", "text_not_present", "text_present", "status_code", "api_json"}
HEX_COLOR = re.compile(r'^#[0-9a-fA-F]{3,8}$')

ALL = list(PLATFORMS.items())
IDS = [name for name, _ in ALL]


def test_platform_database_is_populated():
    assert len(PLATFORMS) > 50


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_required_keys_present(name, plat):
    for key in ("url", "method", "category", "color"):
        assert key in plat, f"{name} is missing '{key}'"


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_url_templates_take_a_username(name, plat):
    assert "{username}" in plat["url"], f"{name} url has no {{username}} placeholder"
    if "check_url" in plat:
        assert "{username}" in plat["check_url"], f"{name} check_url has no placeholder"


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_method_is_known(name, plat):
    assert plat["method"] in VALID_METHODS, f"{name} uses unknown method {plat['method']}"


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_detection_method_has_its_required_evidence(name, plat):
    """Without this key the method silently degrades to always-found."""
    method = plat["method"]
    if method == "text_not_present":
        assert plat.get("not_found_text"), f"{name}: text_not_present needs not_found_text"
    elif method == "text_present":
        assert plat.get("found_text"), f"{name}: text_present needs found_text"
    elif method == "response_url":
        assert plat.get("error_url"), f"{name}: response_url needs error_url"
    elif method == "og_meta":
        assert plat.get("og_not_found") or plat.get("og_found"), (
            f"{name}: og_meta needs og_not_found or og_found — "
            f"without one, every username matches"
        )


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_og_lists_are_non_empty_lists_of_strings(name, plat):
    for key in ("og_not_found", "og_found"):
        if key in plat:
            value = plat[key]
            assert isinstance(value, list) and value, f"{name}: {key} must be a non-empty list"
            assert all(isinstance(s, str) and s for s in value), f"{name}: {key} has a bad entry"


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_status_code_found_list_is_sane(name, plat):
    if plat["method"] == "status_code" and "found" in plat:
        codes = plat["found"]
        assert isinstance(codes, list) and codes, f"{name}: 'found' must be a non-empty list"
        assert all(isinstance(c, int) and 100 <= c <= 599 for c in codes), f"{name}: bad status code"


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_category_is_known(name, plat):
    assert plat["category"] in CATEGORY_META, f"{name} has unknown category {plat['category']}"


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_color_is_a_hex_value(name, plat):
    assert HEX_COLOR.match(plat["color"]), f"{name} has a malformed color {plat['color']}"


@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
def test_bio_patterns_compile_and_capture(name, plat):
    if not plat.get("bio_extract"):
        return
    patterns = plat.get("bio_patterns", {})
    assert patterns, f"{name}: bio_extract is set but bio_patterns is empty"
    for key, pattern in patterns.items():
        compiled = re.compile(pattern)
        assert compiled.groups >= 1, f"{name}.{key} has no capture group"


def test_urls_are_https():
    insecure = [n for n, p in ALL if not p["url"].startswith("https://")]
    assert not insecure, f"non-https platform urls: {insecure}"
