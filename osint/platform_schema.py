"""
Helix: platform definition validation.

Every platform, builtin or loaded from WhatsMyName / Sherlock / Maigret, must
pass these rules before it is scanned. A definition that fails them either
cannot be requested (an unfilled template) or cannot discriminate: an empty
found_text matches every page, which is a guaranteed false positive.
"""

import re
from typing import Dict, List, Tuple

VALID_METHODS = {"og_meta", "text_not_present", "text_present", "status_code",
                 "response_url", "api_json"}

_STRAY_PLACEHOLDER = re.compile(r"\{(?!username\})[^}]*\}")

# A search endpoint answers "found" whenever anything mentions the name: a
# paper on Google Scholar, a channel called "torvalds-fan" on a video search.
# The page echoes the search term, so "the page names the user" passes, and an
# impossible name correctly finds nothing, so the control probe passes too.
# The result is a mention, not an account, so these entries are not scanned.
SEARCH_URL = re.compile(
    r"(?i)(/search(?:page)?(?:[/.?]|$)|[?&](?:q|query|search|keywords?|term|s)=[^&#]*\{username\})")
SEARCH_PROBLEM = "search page: finds mentions of the name, not an account"


def profile_key(url: str) -> str:
    """A profile URL template without scheme, www. or a trailing slash, lower
    case: the same address in two databases is one site, checked once. It is
    also the name a site goes by in the daily site check."""
    u = re.sub(r"^https?://", "", (url or "").strip().lower())
    return re.sub(r"^(www|m|mobile)\.", "", u).rstrip("/")


def is_search_url(url) -> bool:
    return isinstance(url, str) and bool(SEARCH_URL.search(url))


def _url_problems(url, field: str) -> List[str]:
    if not isinstance(url, str) or not url:
        return [f"{field} missing"]
    out = []
    if not url.startswith(("http://", "https://")):
        out.append(f"{field} is not http(s): {url[:60]}")
    if "{username}" not in url:
        out.append(f"{field} has no {{username}}")
    if _STRAY_PLACEHOLDER.search(url):
        out.append(f"{field} has an unfilled placeholder: {url[:60]}")
    if any(c in url for c in " \n\t"):
        out.append(f"{field} contains whitespace")
    # The username may name a subdomain ({username}.tumblr.com) but must never
    # be glued into the rest of the host ("example.com{username}"): then the
    # username decides which server Helix contacts.
    m = re.match(r"^[a-z]+://([^/?#]*)", url, re.I)
    host = m.group(1) if m else ""
    if "{username}" in host and not re.fullmatch(r"\{username\}\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d+)?", host):
        out.append(f"{field} puts the username inside the host name: {url[:60]}")
    return out


def _non_empty_str(value) -> bool:
    return isinstance(value, str) and value.strip() != ""


def problems(pdef: dict) -> List[str]:
    """Reasons this definition is unusable; empty when it is sound."""
    if not isinstance(pdef, dict):
        return ["not a dict"]

    out = _url_problems(pdef.get("url"), "url")
    if "check_url" in pdef:
        out += _url_problems(pdef.get("check_url"), "check_url")

    if is_search_url(pdef.get("check_url") or pdef.get("url")):
        out.append(SEARCH_PROBLEM)

    method = pdef.get("method")
    if method not in VALID_METHODS:
        return out + [f"unknown method {method!r}"]

    if method == "text_not_present" and not _non_empty_str(pdef.get("not_found_text")):
        out.append("text_not_present without not_found_text")
    elif method == "text_present" and not _non_empty_str(pdef.get("found_text")):
        out.append("text_present without found_text: matches every page")
    elif method == "response_url" and not _non_empty_str(pdef.get("error_url")):
        out.append("response_url without error_url")
    elif method == "og_meta":
        lists = [pdef.get("og_not_found"), pdef.get("og_found")]
        if not any(isinstance(values, list) and any(_non_empty_str(s) for s in values) for values in lists):
            out.append("og_meta without og_not_found/og_found: matches every page")
    elif method == "status_code":
        codes = pdef.get("found", [200])
        if not (isinstance(codes, list) and codes
                and all(isinstance(c, int) and 100 <= c <= 599 for c in codes)):
            out.append(f"status_code with bad 'found' codes {codes!r}")

    if "found_texts" in pdef and not (isinstance(pdef["found_texts"], list) and pdef["found_texts"]
                                      and all(_non_empty_str(t) for t in pdef["found_texts"])):
        out.append("found_texts is not a list of texts")
    headers = pdef.get("headers")
    if headers is not None and not (isinstance(headers, dict) and all(
            isinstance(k, str) and isinstance(v, str) and k.strip()
            and not re.search(r"[\r\n]", k + v) for k, v in headers.items())):
        out.append("headers is not a map of header names to single-line values")

    fallbacks = pdef.get("fallbacks")
    if fallbacks is not None:
        if not isinstance(fallbacks, list) or not all(isinstance(fb, dict) for fb in fallbacks):
            out.append("fallbacks is not a list of definitions")
        else:
            for i, fb in enumerate(fallback_defs(pdef)):
                if "fallbacks" in fb:
                    out.append(f"fallback {i + 1} has fallbacks of its own")
                out += [f"fallback {i + 1}: {why}" for why in problems({k: v for k, v in fb.items()
                                                                        if k != "fallbacks"})]

    return out


# What a fallback rule takes from its site: where the profile lives and how
# the site is labelled. How to ask and how to read the answer are its own.
_INHERITED = ("url", "category", "color", "source", "nsfw")


def fallback_defs(pdef: dict) -> List[dict]:
    """
    The other ways to ask this site, each a complete definition.

    A site may list `fallbacks`: more rules for the same account, used when
    the first one gets no clear answer (a fediverse server whose lookup API is
    rate-limited still answers WebFinger). Each is used as a whole: the hit
    and the made-up names of the control probe are always read by one rule.
    """
    out = []
    for fb in (pdef or {}).get("fallbacks") or []:
        if isinstance(fb, dict):
            out.append({**{k: pdef[k] for k in _INHERITED if k in pdef}, **fb})
    return out


def filter_valid(platforms: Dict[str, dict]) -> Tuple[Dict[str, dict], Dict[str, List[str]]]:
    """Split a platform map into (usable, {name: problems}) ."""
    good, bad = {}, {}
    for name, pdef in (platforms or {}).items():
        issues = problems(pdef)
        if issues:
            bad[name] = issues
        else:
            good[name] = pdef
    return good, bad
