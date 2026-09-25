"""
Helix — Approved-subject identifiers.

Breach and dark-web lookups send an identifier to a third party, so only
identifiers tied to the subject are queried:
  - what the analyst supplied (-u, -e), and
  - what a harvested account exposes, only when that account is corroborated
    as the subject's (identity confidence MEDIUM or HIGH). An email pulled
    from a username-only match could belong to a stranger.
"""

from typing import Dict, List, Tuple

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
