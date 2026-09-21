"""
Helix — GitHub Deep Recon + Timezone Inference
Uses GitHub REST API (free: 60 req/hr unauthenticated, 5000/hr with GITHUB_TOKEN).
Extracts: real emails from commits, orgs, languages, timezone (≥15 commits),
npm packages, top repos. Handles noreply addresses and rate limits gracefully.
"""
import asyncio, aiohttp, os, re
from datetime import datetime, timezone
from collections import Counter
from typing import Dict, List, Optional, Set
from osint import netconfig

API = "https://api.github.com"


def _gh_headers() -> Dict:
    h = {"Accept": "application/vnd.github.v3+json",
         "User-Agent": "Helix-OSINT/3.0 (security research)"}
    token = os.environ.get("GITHUB_TOKEN","")
    if token:
        h["Authorization"] = f"token {token}"
    return h


async def _get(session: aiohttp.ClientSession, url: str) -> Optional[any]:
    try:
        async with session.get(url, headers=_gh_headers(),
                               timeout=aiohttp.ClientTimeout(total=12),
                               ssl=False) as resp:
            if resp.status == 200: return await resp.json()
            if resp.status == 403: return {"_rate_limited": True}
            return None
    except Exception:
        return None


def _infer_timezone(timestamps: List[datetime]) -> Dict:
    """
    Find the UTC offset that places the most commits in 07:00–23:00 local time.
    Requires ≥15 commits for a reliable estimate.
    """
    if len(timestamps) < 15:
        return {
            "timezone":    "insufficient data",
            "note":        f"need ≥15 commits, have {len(timestamps)}",
            "active_hours": [],
        }

    utc_hours = [dt.hour for dt in timestamps]
    best_offset, best_score = 0, -1

    for offset in range(-12, 13):
        local = [(h + offset) % 24 for h in utc_hours]
        score  = sum(1 for h in local if 7 <= h <= 23)
        if score > best_score:
            best_score, best_offset = score, offset

    sign   = "+" if best_offset >= 0 else "-"
    tz_str = f"UTC{sign}{abs(best_offset):02d}:00"
    conf   = int(best_score / len(utc_hours) * 100)

    local_hours  = [(h + best_offset) % 24 for h in utc_hours]
    hour_counter = Counter(local_hours)
    peak_hour    = hour_counter.most_common(1)[0][0]

    return {
        "timezone":     tz_str,
        "confidence":   f"{conf}%",
        "peak_hour":    f"{peak_hour:02d}:00–{(peak_hour+2)%24:02d}:00 local",
        "active_hours": sorted(set(local_hours)),
        "sample_size":  len(timestamps),
    }


def _is_real_email(email: str) -> bool:
    """Filter out GitHub noreply addresses and other synthetic emails."""
    fake = ["noreply.github.com", "users.noreply", "example.com",
            "localhost", "github.com", "actions@"]
    return "@" in email and not any(f in email for f in fake)


async def run(username: str) -> Dict:
    result = {
        "username":    username,
        "name":        "", "location": "", "company": "", "blog": "",
        "emails":      [],
        "orgs":        [],
        "languages":   {},
        "top_repos":   [],
        "timezone":    {},
        "npm_packages": [],
        "commit_count": 0,
        "rate_limited": False,
        "error":        None,
    }

    emails:     Set[str]      = set()
    timestamps: List[datetime] = []

    connector = netconfig.build_connector(limit=6, force_close=True)
    async with netconfig.new_session(connector=connector) as session:

        # ── 1. Profile ────────────────────────────────────────────────────────
        profile = await _get(session, f"{API}/users/{username}")
        if not profile or (isinstance(profile, dict) and profile.get("_rate_limited")):
            result["rate_limited"] = True
            result["error"] = "GitHub API rate limited — set GITHUB_TOKEN for 5000 req/hr"
            return result
        if isinstance(profile, dict) and profile.get("message") == "Not Found":
            result["error"] = "User not found on GitHub"
            return result

        result["name"]     = profile.get("name","") or ""
        result["location"] = profile.get("location","") or ""
        result["company"]  = (profile.get("company","") or "").lstrip("@")
        result["blog"]     = profile.get("blog","") or ""
        if profile.get("email") and _is_real_email(profile["email"]):
            emails.add(profile["email"])

        # ── 2. Orgs ───────────────────────────────────────────────────────────
        orgs = await _get(session, f"{API}/users/{username}/orgs")
        if orgs and isinstance(orgs, list):
            result["orgs"] = [
                {"name": o.get("login",""),
                 "description": (o.get("description","") or "")[:80]}
                for o in orgs[:10]
            ]

        # ── 3. Repos + languages ──────────────────────────────────────────────
        repos = await _get(session, f"{API}/users/{username}/repos?per_page=30&sort=pushed")
        lang_counter: Counter = Counter()
        if repos and isinstance(repos, list):
            for r in repos:
                if r.get("language"): lang_counter[r["language"]] += 1
            result["languages"] = dict(lang_counter.most_common(8))
            result["top_repos"] = [
                {"name":  r.get("name",""),
                 "stars": r.get("stargazers_count",0),
                 "lang":  r.get("language",""),
                 "desc":  (r.get("description","") or "")[:60],
                 "url":   r.get("html_url","")}
                for r in sorted(repos, key=lambda x: x.get("stargazers_count",0), reverse=True)[:5]
            ]
        else:
            repos = []

        # ── 4. Commit emails + timestamps (non-fork repos only) ───────────────
        checked = 0
        for repo in (repos or [])[:10]:
            if checked >= 6: break
            if repo.get("fork"): continue
            rname   = repo.get("name","")
            commits = await _get(session,
                f"{API}/repos/{username}/{rname}/commits?author={username}&per_page=40")
            await asyncio.sleep(0.12)

            if not commits or not isinstance(commits, list):
                continue
            checked += 1
            for c in commits:
                author = c.get("commit",{}).get("author",{})
                email  = author.get("email","")
                if email and _is_real_email(email):
                    emails.add(email)
                date_str = author.get("date","")
                if date_str:
                    try:
                        dt = datetime.fromisoformat(date_str.replace("Z","+00:00"))
                        timestamps.append(dt.astimezone(timezone.utc))
                    except Exception:
                        pass

        result["commit_count"] = len(timestamps)
        result["emails"]       = sorted(emails)

        # ── 5. Timezone inference ─────────────────────────────────────────────
        if timestamps:
            result["timezone"] = _infer_timezone(timestamps)

        # ── 6. npm cross-reference ────────────────────────────────────────────
        npm = await _get(session,
            f"https://registry.npmjs.org/-/v1/search?text=maintainer:{username}&size=5")
        if npm and isinstance(npm, dict) and "objects" in npm:
            result["npm_packages"] = [
                {"name":    o["package"].get("name",""),
                 "version": o["package"].get("version",""),
                 "desc":    (o["package"].get("description","") or "")[:60],
                 "url":     o["package"].get("links",{}).get("npm","")}
                for o in npm["objects"][:5]
            ]

    return result
