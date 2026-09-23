"""
Helix — Identity confidence per finding.

Detection confidence (the existing `confidence` field) answers "does this
account exist?". Identity confidence answers the investigator's actual
question: "is this account the subject?". It is computed only from
independent selectors that agree, never from how convincing a page looks.

Selectors:
  username    exact username match — every finding has it, so alone it is weak
  avatar      perceptual-hash match with another found profile
  cross_link  this profile's bio links to another found profile, or vice versa
  email       the same platform was also confirmed from the subject's email
  real_name   the page names the real name extracted from a *different* profile
  location    the profile's stated location agrees with the known subject location

Rules:
  - a single selector is never HIGH
  - HIGH needs three selectors, or two where one is strong (avatar/cross_link/email)
  - status-code-only detection caps a finding at MEDIUM
  - a stated location that conflicts with the subject caps a finding at LOW
"""

import re
from typing import Dict, Iterable, List, Optional

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
STRONG_SELECTORS = {"avatar", "cross_link", "email"}

_SELECTOR_LABELS = {
    "username":   "same username",
    "avatar":     "same avatar",
    "cross_link": "bio cross-link",
    "email":      "confirmed by email",
    "real_name":  "real name matches",
    "location":   "location agrees",
}


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _same_platform(a: str, b: str) -> bool:
    na, nb = _norm(a), _norm(b)
    if len(na) < 3 or len(nb) < 3:
        return na == nb and bool(na)
    return na == nb or na in nb or nb in na


def _cross_links(found: List[dict], username: str) -> Dict[str, set]:
    """platform → set of other found platforms it is linked with (either direction)."""
    links: Dict[str, set] = {r["platform"]: set() for r in found}
    u = (username or "").lower()
    for r in found:
        for key, handle in (r.get("bio_links") or {}).items():
            if key == "website" or (handle or "").lower().strip("@") != u:
                continue
            for other in found:
                if other is not r and _same_platform(key, other["platform"]):
                    links[r["platform"]].add(other["platform"])
                    links[other["platform"]].add(r["platform"])
    return links


def _avatar_partners(phash_matches: Iterable[dict]) -> Dict[str, set]:
    partners: Dict[str, set] = {}
    for m in phash_matches or []:
        a, b = m.get("platform_a"), m.get("platform_b")
        if a and b:
            partners.setdefault(a, set()).add(b)
            partners.setdefault(b, set()).add(a)
    return partners


def _email_platforms(email_results: Iterable[dict]) -> List[str]:
    return [r.get("platform", "") for r in email_results or [] if r.get("found")]


def _grade(selectors: List[str], detection: str, conflict: bool) -> str:
    if conflict:
        return LOW
    n = len(selectors)
    strong = any(s in STRONG_SELECTORS for s in selectors)

    if n >= 3 or (n >= 2 and strong):
        grade = HIGH
    elif n >= 2:
        grade = MEDIUM
    else:
        grade = LOW

    if grade == HIGH and detection == "low":
        grade = MEDIUM
    return grade


def score_identity(results: List[dict], username: str,
                   phash_matches: Optional[List[dict]] = None,
                   email_results: Optional[List[dict]] = None,
                   real_name: str = "", real_name_source: str = "",
                   subject_countries: Iterable[str] = ()) -> Dict[str, int]:
    """
    Attach `identity_confidence`, `selectors` and `evidence` to every found
    result. Returns a count per grade.
    """
    subject   = set(subject_countries or ())
    found     = [r for r in results if r.get("found")]
    links     = _cross_links(found, username)
    avatars   = _avatar_partners(phash_matches)
    email_hit = _email_platforms(email_results)
    name_l    = (real_name or "").lower().strip()

    counts = {HIGH: 0, MEDIUM: 0, LOW: 0}
    for r in found:
        plat      = r["platform"]
        selectors = ["username"]
        evidence  = [_SELECTOR_LABELS["username"]]

        if avatars.get(plat):
            selectors.append("avatar")
            evidence.append(f"same avatar as {', '.join(sorted(avatars[plat]))}")

        if links.get(plat):
            selectors.append("cross_link")
            evidence.append(f"bio cross-link with {', '.join(sorted(links[plat]))}")

        if any(_same_platform(plat, e) for e in email_hit):
            selectors.append("email")
            evidence.append(_SELECTOR_LABELS["email"])

        og = (r.get("og_title") or "").lower()
        if name_l and plat != real_name_source and name_l in og:
            selectors.append("real_name")
            evidence.append(f"names '{real_name}' (first seen on {real_name_source})")

        stated = set(r.get("location_countries") or [])
        if subject and stated & subject and not r.get("location_conflict"):
            selectors.append("location")
            evidence.append(f"location agrees ({', '.join(sorted(stated & subject))})")

        conflict = bool(r.get("location_conflict"))
        if conflict:
            evidence.append(f"capped: {r.get('location_note') or 'location conflict'}")
        if r.get("confidence") == "low" and not conflict and len(selectors) >= 2:
            evidence.append("capped: detection is status-code only")

        grade = _grade(selectors, r.get("confidence", "low"), conflict)
        r["identity_confidence"] = grade
        r["selectors"] = selectors
        r["evidence"]  = evidence
        counts[grade] += 1

    return counts
