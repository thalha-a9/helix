"""Helix — WhatsMyName Adapter (v1.2.0)

Key improvements over v1.1:
  - Pre-flight filter: registration/availability API URLs are blocked before
    they enter the platform map. These return 200 to mean "username is free
    to register", not "profile exists". Helix used to misread this as a hit.
  - Dead-site filter: urls for known-dead/parked hostnames are skipped.
  - uri_check URLs that match known bad patterns get method upgraded to
    text_present or text_not_present where e_string/m_string exist, so the
    status_code fallback (the root cause of most WMN false positives) is
    used only when no content-based signal is available.
"""
import re
import aiohttp
from typing import Dict
from urllib.parse import urlparse
from osint import netconfig

WMN_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/"
    "main/wmn-data.json"
)

_CATEGORY_MAP = {
    "social":   "social",
    "gaming":   "gaming",
    "music":    "content",
    "video":    "content",
    "photo":    "content",
    "art":      "content",
    "blog":     "content",
    "news":     "content",
    "coding":   "dev",
    "tech":     "dev",
    "finance":  "other",
    "dating":   "other",
    "forum":    "forum",
    "adult":    "other",
    "sport":    "other",
    "career":   "other",
    "general":  "other",
}

# ── Registration / availability API URLs — block these entirely ───────────────
# A 200 on these means the username is FREE, not that a profile exists.
_BLOCKED_URL_PATTERNS = [
    "checkusername",
    "check-username",
    "check_username",
    "username-available",
    "username_available",
    "/username/available",
    "validate/username",
    "user/exist/",
    "/accounts/lookup",
    "2017-06-30/users",           # Duolingo
    "api-proxy/bbc/get",          # BodyBuilding.com
    "api/accounts/validate",      # BoardGameGeek
    "wp-json/wporg/v1/username",  # WordPress.org
    "GetCard/",                   # visnesscard — returns 422 for all requests
    "tapitag/api/v1/",            # TAPiTAG — RF number, not user profile
    "api/user/exist/",            # TryHackMe
    "webapi/3.2/users/check",     # Quizlet
    "/graphql",                   # GraphQL availability endpoints (Znanija etc.)
    "NickAvailability",           # Znanija specific — isAvailable:false ≠ profile exists
    "operationName=NickAvailability", # Znanija full pattern
    # Search pages masquerading as profile URLs — these return results for any query
    "search?q=",             # generic search pages
    "summoners/search",      # OP.GG search — not a profile
    "quick=1&type=core_members", # search pages
    "/search/query",         # Scribd search
    "userid=",               # Yelp by ID — not a real profile lookup
    "yandex.ru/collections/api/users/", # Yandex collections API
    "showuser=",             # forum search by user
    "PAGE_NAME=profile_view&UID=", # forum profile by numeric ID
    "user_details?userid=",  # Yelp user details by ID
    "soundgym.co/member/profile?m=", # param-based
    "freepost.cgi/user/public/", # old CGI
    "/search/?q=",           # search pages
]

# ── Known dead / permanently down hostnames ───────────────────────────────────
_DEAD_HOSTS = {
    "taringa.net",         # shut down 2024
    "lor.sh",              # dead Mastodon instance
    "hiberworld.com",      # shut down
    "waytohey.com",        # dead
    "vip-blog.com",
    "chatango.com",        # SSL broken / dead
    "ultrasdiary.pl",      # dead
    "wego.social",         # parked
    "mini.zbiornik.com",   # adult, consistently broken
    "codeproject.com",     # GoDaddy parked — no active user profiles
    "visnesscard.com",     # API 422 for all requests
    "kipin.app",           # 404 for all profiles — stale WMN entry
    "paypal.com",          # paypal.me CAPTCHA on any URL, real or not
    "tinder.com",          # login gate, profiles not publicly viewable
    "zbiornik.com",        # adult login gate
    "mini.zbiornik.com",   # adult login gate
    "bentbox.co",          # age-verify redirect for all visitors
    "my.flightradar24.com",# login gate
    "voices.com",          # redirects to talent search
    "vivino.com",          # login gate
    "livemaster.ru",       # CAPTCHA block
    "magix.info",          # login gate
    "forum.igromania.ru",  # CAPTCHA / login
    "forum.3dnews.tech",   # CAPTCHA / login
    "blog.myfitnesspal.com",# empty author page
    "kwork.ru",            # login / maintenance gate
    "slideshare.net",      # page no longer exists for all non-existent users
    "scribd.com",          # search page — not a profile URL
    "search.ddosecrets.com",# redirects to unrelated domain
    "ddosecrets.com",      # same
    # Confirmed soft-404 platforms — username with ._ always returns 200 but no profile
    "ebay.com",            # JS-rendered soft-404 — username format invalid for eBay
    "brickset.com",        # soft-404 as 200
    "hosted.weblate.org",  # soft-404 as 200
    "weblate.org",         # same
    "pypi.org",            # user page 200 even when user doesn't exist
    "minecraftlist.com",   # player not found but 200
    "arsmate.com",         # usuario no encontrado but 200
    "dot.cards",           # this username does not exist but 200
    "forum.getmonero.org", # empty response for missing users
    "xhamster.com",        # adult platform, login gate
    "patriots.win",        # "invalid user" served as 200 OK
}

# ── Known bad e_code=200 + no content check platforms — mark unverifiable ────
# These use pure status_code method but the 200 is meaningless (soft-404).
# We keep them but mark source so the verifier can apply extra scrutiny.
_STATUS_CODE_ONLY_SUSPICIOUS = {
    "mapmytracks.com",
    "brickset.com",
    "minecraftlist.com",
    "arsmate.com",
    "dot.cards",
    "weblate.org",
    "forum.getmonero.org",
    "ebay.com",              # soft-404 served as 200
    "pypi.org",              # user page 200 even with no packages
}


def _is_blocked_url(url: str) -> bool:
    u = url.lower()
    return any(p in u for p in _BLOCKED_URL_PATTERNS)


def _is_dead_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return any(dead in host for dead in _DEAD_HOSTS)
    except Exception:
        return False


def _is_suspicious_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return any(s in host for s in _STATUS_CODE_ONLY_SUSPICIOUS)
    except Exception:
        return False


# NSFW categories to filter by default
_NSFW_CATEGORIES = {"adult"}

async def fetch_wmn_platforms(timeout: int = 30, include_nsfw: bool = False) -> Dict[str, dict]:
    async with netconfig.new_session() as session:
        try:
            async with session.get(
                WMN_URL, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                data = await resp.json(content_type=None)
        except Exception as e:
            raise RuntimeError(f"WhatsMyName fetch failed: {e}")

    sites = data.get("sites", [])
    if not sites:
        raise RuntimeError("WhatsMyName data empty or format changed")

    platforms = {}
    blocked   = 0
    dead      = 0

    for site in sites:
        name     = site.get("name", "")
        uri      = site.get("uri_check", "")
        e_string = site.get("e_string", "")
        m_string = site.get("m_string", "")
        e_code   = site.get("e_code", 200)
        raw_cat  = site.get("category", "").lower()
        category = _CATEGORY_MAP.get(raw_cat, "other")

        if not name or not uri or "{account}" not in uri:
            continue

        # Filter NSFW by default
        if not include_nsfw and raw_cat in _NSFW_CATEGORIES:
            continue

        url = uri.replace("{account}", "{username}")

        # Hard block: registration/availability APIs
        if _is_blocked_url(url):
            blocked += 1
            continue

        # Hard block: dead/parked hosts
        if _is_dead_host(url):
            dead += 1
            continue

        # Build platform definition
        if m_string:
            pdef = {
                "url":            url,
                "method":         "text_not_present",
                "not_found_text": m_string,
                "category":       category,
                "color":          "#a78bfa",
                "source":         "wmn",
            }
        elif e_string:
            pdef = {
                "url":        url,
                "method":     "text_present",
                "found_text": e_string,
                "category":   category,
                "color":      "#a78bfa",
                "source":     "wmn",
            }
        else:
            # Pure status_code — note this is the most error-prone method.
            # Tag suspicious hosts so the verifier applies extra scrutiny.
            extra = {"wmn_status_only": True}
            if _is_suspicious_host(url):
                extra["wmn_soft404_risk"] = True
            pdef = {
                "url":      url,
                "method":   "status_code",
                "found":    [e_code],
                "category": category,
                "color":    "#a78bfa",
                "source":   "wmn",
                **extra,
            }

        platforms[name] = pdef

    # ── Post-process: fix known WMN URL issues ───────────────────────────────
    # Bluesky: WMN sends bsky.app/profile/{username} (SPA, unreliable).
    # Override to use AT Protocol API which gives true 200/400.
    if "Bluesky" in platforms or "Bluesky 1" in platforms:
        for bsky_key in ["Bluesky", "Bluesky 1", "BlueSky"]:
            if bsky_key in platforms:
                platforms[bsky_key].update({
                    "url":       "https://bsky.app/profile/{username}.bsky.social",
                    "check_url": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={username}.bsky.social",
                    "method":    "status_code",
                    "found":     [200],
                })

    # Patriots Win: WMN URL is correct, keep as-is (confirmed real profile)
    # Poe.com: WMN URL is correct, keep as-is (confirmed real profile)
    platforms["__wmn_filter_stats__"] = {
        "_meta":   True,
        "blocked": blocked,
        "dead":    dead,
        "loaded":  len(platforms) - 1,
    }

    return platforms


async def load_with_fallback(timeout: int = 30, include_nsfw: bool = False) -> Dict[str, dict]:
    try:
        raw = await fetch_wmn_platforms(timeout=timeout, include_nsfw=include_nsfw)
        # Strip internal meta entry before returning to caller
        stats = raw.pop("__wmn_filter_stats__", {})
        _b = stats.get("blocked", 0)
        _d = stats.get("dead", 0)
        if _b or _d:
            import sys
            print(
                f"  [wmn] Pre-flight filter: blocked {_b} registration-API URL(s), "
                f"skipped {_d} dead-host URL(s)",
                file=sys.stderr,
            )
        return raw
    except Exception as e:
        print(
            f"\n  [!] WhatsMyName warning: {e}\n"
            f"  [!] Try increasing timeout with --wmn-timeout 60\n"
        )
        return {}
