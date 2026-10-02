"""
Helix — Approved-subject identifiers.

Breach and dark-web lookups send an identifier to a third party, so only
identifiers tied to the subject are queried:
  - what the analyst supplied (-u, -e), and
  - what a harvested account exposes, only when that account is corroborated
    as the subject's (identity confidence MEDIUM or HIGH). An email pulled
    from a username-only match could belong to a stranger.
"""

import re
from typing import Dict, List, Optional, Tuple

_TRUSTED = ("HIGH", "MEDIUM")


def approved_identifiers(email: str, username: str, results: List[dict],
                         github_intel: Dict, real_name: str = "",
                         real_name_source: str = "") -> Tuple[Dict, List[str]]:
    """→ ({"emails": [...], "terms": [...]}, [reasons for held-back identifiers])"""
    identity = {r["platform"]: r.get("identity_confidence") or "LOW"
                for r in results if r.get("found")}
    emails: List[str] = []
    held: List[str] = []

    def add_email(e: str):
        e = (e or "").strip().lower()
        if e and e not in emails:
            emails.append(e)

    if email:
        add_email(email)

    gh = github_intel or {}
    gh_emails = [] if gh.get("error") else gh.get("emails") or []
    if gh_emails:
        grade = identity.get("GitHub", "LOW")
        if grade in _TRUSTED:
            for e in gh_emails:
                add_email(e)
        else:
            held.append(f"{len(gh_emails)} GitHub commit email(s) — the GitHub account is "
                        f"identity {grade}; corroborate it (e.g. --phash, -e) first")

    terms: List[str] = []
    if username:
        terms.append(username)
    terms.extend(emails)
    if real_name:
        grade = identity.get(real_name_source, "LOW")
        if grade in _TRUSTED:
            terms.append(real_name)
        else:
            held.append(f"name '{real_name}' from {real_name_source} — that account is "
                        f"identity {grade}")
    return {"emails": emails, "terms": terms}, held


# Words that make an og:title site boilerplate, not a person's name.
_NOT_A_NAME = {"profile", "profiles", "user", "users", "account", "page", "home", "official",
               "member", "members", "community", "channel", "portfolio", "applets", "blog",
               "login", "log", "sign", "signup", "welcome", "error", "not", "found", "on",
               "the", "of", "and", "at", "s", "chess", "rating", "games", "stream", "streams",
               "music", "videos", "photos", "listen", "watch", "follow", "collection"}


def real_name_from_title(og_title: str, platform: str, username: str) -> Optional[str]:
    """
    A display name from an og:title such as "Jane Roe (@janeroe) • Instagram"
    or "Jane Roe - Dribbble". Returns None unless the result looks like a
    person's name: 2-4 capitalised words, none of them site boilerplate or the
    platform's name ("HackerOne profile - jack" is not a name).
    """
    if not og_title:
        return None
    t = re.sub(r"\s*[(\[]@?[^)\]]*[)\]]", " ", og_title)        # "(@janeroe)"
    t = re.split(r"\s+[|\-\u2013\u2014\u00b7\u2022:]\s+|\s*[|\u00b7\u2022]\s*", t)[0]
    t = " ".join(t.split()).strip(" .,'\"")
    plat = {w for w in re.split(r"[^a-z0-9]+", (platform or "").lower()) if w}
    m = re.match(r"(.+?)\s+(?:on|at|is on)\s+(\S+)!?$", t)          # "Linus Torvalds on Snapchat"
    if m and m.group(2).lower().strip("!.") in plat:
        t = m.group(1)
    words = t.split()
    if not 2 <= len(words) <= 4:
        return None
    for w in words:
        lw = w.lower().strip(".,'\"")
        if (not w[0].isupper() or not re.fullmatch(r"[^\W\d_][\w'.-]*", w)
                or lw in _NOT_A_NAME or lw in plat):
            return None
    return t
