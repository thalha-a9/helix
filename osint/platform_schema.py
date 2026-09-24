"""
Helix — platform definition validation.

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

    method = pdef.get("method")
    if method not in VALID_METHODS:
        return out + [f"unknown method {method!r}"]

    if method == "text_not_present" and not _non_empty_str(pdef.get("not_found_text")):
        out.append("text_not_present without not_found_text")
    elif method == "text_present" and not _non_empty_str(pdef.get("found_text")):
        out.append("text_present without found_text — matches every page")
    elif method == "response_url" and not _non_empty_str(pdef.get("error_url")):
        out.append("response_url without error_url")
    elif method == "og_meta":
        lists = [pdef.get("og_not_found"), pdef.get("og_found")]
        if not any(isinstance(l, list) and any(_non_empty_str(s) for s in l) for l in lists):
            out.append("og_meta without og_not_found/og_found — matches every page")
    elif method == "status_code":
        codes = pdef.get("found", [200])
        if not (isinstance(codes, list) and codes
                and all(isinstance(c, int) and 100 <= c <= 599 for c in codes)):
            out.append(f"status_code with bad 'found' codes {codes!r}")

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
