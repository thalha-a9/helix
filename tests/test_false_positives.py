"""
False-positive harness.

For every platform definition, synthesise the response that platform serves for
a username that does not exist, push it through the real detection code and the
real verifier, and assert nothing is reported as found. A platform whose
definition has drifted — a changed not-found string, a typo'd og key, a missing
error_url — shows up here as a hard failure instead of as a bad finding in an
investigation report.

The mirror direction is covered too: a realistic profile page must still be
detected, so tightening detection cannot silently zero out the tool.
"""

import pytest

from osint import checker
from osint.platforms import PLATFORMS
from osint.verifier import run_local_verifier

ABSENT_USERNAME = "zzqx9nonexistentuser42"
PRESENT_USERNAME = "janeroe"

ALL = list(PLATFORMS.items())
IDS = [name for name, _ in ALL]


def _blank_result(name, plat, username):
    return {
        "platform": name,
        "url": plat["url"].replace("{username}", username),
        "category": plat["category"], "color": plat["color"],
        "found": False, "error": None, "confidence": "low",
        "bio_links": {}, "target_type": "username",
        "source": plat.get("source", "builtin"),
        "status_code": None, "og_title": "",
    }


def _absent_response(plat):
    """(status, body) that this platform serves for a non-existent user."""
    method = plat["method"]

    if method == "status_code":
        return 404, "<html><body>Not Found</body></html>"

    if method == "text_not_present":
        marker = plat["not_found_text"]
        return 200, f"<html><body><h1>{marker}</h1></body></html>"

    if method == "text_present":
        return 200, "<html><body>Nothing here</body></html>"

    if method == "response_url":
        return 200, "<html><body>Not Found</body></html>"

    if method == "og_meta":
        if plat.get("og_not_found"):
            marker = plat["og_not_found"][0]
            return 200, f'<html><head><meta property="og:title" content="{marker}">' \
                        f'</head><body>not found</body></html>'
        # og_found platforms: a page whose title never matches the username
        return 200, '<html><head><meta property="og:title" content="Sign up">' \
                    '</head><body>not found</body></html>'

    return 404, ""


def _absent_final_url(plat, username):
    if plat["method"] == "response_url":
        return plat.get("error_url", "")
    return plat["url"].replace("{username}", username)


@pytest.mark.asyncio
@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
async def test_absent_user_is_never_reported_found(name, plat):
    status, body = _absent_response(plat)
    result = _blank_result(name, plat, ABSENT_USERNAME)
    probe = plat.get("check_url", plat["url"]).replace("{username}", ABSENT_USERNAME)

    await checker._apply(result, plat, ABSENT_USERNAME, status, body,
                         _absent_final_url(plat, ABSENT_USERNAME), probe)
    results, _ = run_local_verifier([result], ABSENT_USERNAME)

    assert results[0]["found"] is False, (
        f"{name} reports a non-existent user as found — "
        f"method={plat['method']}, status={status}"
    )


@pytest.mark.asyncio
async def test_zero_false_positives_across_the_whole_database():
    """Aggregate view: the count must be exactly zero, and names are reported."""
    false_positives = []

    for name, plat in ALL:
        status, body = _absent_response(plat)
        result = _blank_result(name, plat, ABSENT_USERNAME)
        probe = plat.get("check_url", plat["url"]).replace("{username}", ABSENT_USERNAME)

        await checker._apply(result, plat, ABSENT_USERNAME, status, body,
                             _absent_final_url(plat, ABSENT_USERNAME), probe)
        results, _ = run_local_verifier([result], ABSENT_USERNAME)
        if results[0]["found"]:
            false_positives.append(name)

    assert false_positives == [], (
        f"{len(false_positives)}/{len(ALL)} platforms produced a false positive: "
        f"{false_positives}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("name,plat", ALL, ids=IDS)
async def test_present_user_is_still_detected(name, plat):
    """Detection must not be so strict that a real profile is missed."""
    method = plat["method"]
    result = _blank_result(name, plat, PRESENT_USERNAME)
    probe = plat.get("check_url", plat["url"]).replace("{username}", PRESENT_USERNAME)
    final = plat["url"].replace("{username}", PRESENT_USERNAME)

    if method == "status_code":
        status = (plat.get("found") or [200])[0]
        body = f"<html><body><h1>{PRESENT_USERNAME}</h1></body></html>"
    elif method == "text_not_present":
        status, body = 200, f"<html><body><h1>{PRESENT_USERNAME}</h1></body></html>"
    elif method == "text_present":
        marker = plat["found_text"].replace("{username}", PRESENT_USERNAME)
        status, body = 200, f"<html><body>{marker}</body></html>"
    elif method == "response_url":
        status, body = 200, f"<html><body>{PRESENT_USERNAME}</body></html>"
    elif method == "og_meta":
        if plat.get("og_found"):
            title = plat["og_found"][0].replace("{username}", PRESENT_USERNAME)
        else:
            title = f"{PRESENT_USERNAME} (@{PRESENT_USERNAME})"
        status = 200
        body = f'<html><head><meta property="og:title" content="{title}">' \
               f'</head><body>{PRESENT_USERNAME}</body></html>'
    else:
        pytest.skip(f"unhandled method {method}")

    await checker._apply(result, plat, PRESENT_USERNAME, status, body, final, probe)

    assert result["found"] is True, (
        f"{name} failed to detect an existing profile — method={method}"
    )
