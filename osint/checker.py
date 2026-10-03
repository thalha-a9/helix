"""
Helix v2.0 — Async Checker Engine
"""

import asyncio
import aiohttp
import hashlib
import re
import random
from urllib.parse import urlparse
from typing import Optional
from osint.platforms import PLATFORMS
from osint import netconfig

try:
    from curl_cffi.requests import AsyncSession as CurlSession
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
]

def _headers() -> dict:
    return {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9"]),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "DNT": "1",
    }

TIMEOUT     = aiohttp.ClientTimeout(total=14, connect=7)
_MAX_BODY_BYTES = 512 * 1024  # 512KB cap — prevents memory exhaustion (#14)
MAX_RETRIES = 2
# Large database scans: one short attempt per site. Thousands of dead hosts
# retried with long timeouts would otherwise dominate the run time.
FAST_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)
FAST_SCAN_THRESHOLD = 200


# ── WAF / bot-check page detection ───────────────────────────────────────────
_WAF_SIGNATURES = [
    "just a moment...", "checking your browser",
    "enable javascript and cookies", "ddos protection by cloudflare",
    "attention required!", "incapsula incident",
    "please verify you are a human",
]


# ── API response "not found" detection ───────────────────────────────────────
_API_URL_PATTERNS = [
    "/api/", "?username=", "/wp-json/", "_json", "checkusername",
    "validate/username", "user/exist/", "/accounts/lookup", "username_available",
    "2017-06-30/users", "api-proxy", "/accounts/", "check-username",
]

_API_NOT_FOUND_PATTERNS = [
    # Username invalid / not found patterns from real API responses
    '"valid":false',        '"valid": false',
    '"available":true',     '"available": true',   # available=true → not registered
    '"users":[]',           '"users": []',
    '"data":""',            '"data": ""',
    '"data":[]',            '"data": []',
    '"msg":"invalid',       '"msg": "invalid',
    '"isValid":false',      '"isValid": false',
    '"exists":false',       '"exists": false',
    '"registered":false',   '"registered": false',
    '"found":false',        '"found": false',
    '"error":404',
    '{"error"',             # any JSON error response
    '"message":"Not Found"', '"status":"not_found"',
    'invalid username',     'improper_format',
    '"result":"ko"',        '"result": "ko"',
]

_DEAD_SITE_PATTERNS = [
    "something new is coming", "site is dead", "rip 2004",
    "under maintenance", "domain is for sale", "parked by godaddy",
    "this domain is parked", "buy this domain",
]

def _is_api_url(url: str) -> bool:
    u = url.lower()
    return any(p in u for p in _API_URL_PATTERNS)

def _api_says_not_found(text: str) -> bool:
    """Return True if an API response body explicitly says user doesn't exist."""
    t = text.strip()
    # Pure empty array or empty object
    if t in ("[]", "{}", '{"users":[]}'):
        return True
    return any(p in t for p in _API_NOT_FOUND_PATTERNS)

def _is_dead_site(text: str) -> bool:
    t = text.lower()[:2000]
    return any(p in t for p in _DEAD_SITE_PATTERNS)

def _is_waf_page(text: str) -> bool:
    t = text[:3000].lower()
    return any(sig in t for sig in _WAF_SIGNATURES)

def _dynamic_concurrency(n: int) -> int:
    if n <= 50:  return 20
    if n <= 200: return 40
    return 60

def _extract_og_tag(html: str, prop: str) -> Optional[str]:
    for pat in [
        rf'<meta[^>]+(?:property|name)=["\']og:{re.escape(prop)}["\'][^>]+content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']og:{re.escape(prop)}["\']',
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m: return m.group(1).strip()
    return None

# Markup namespaces, CDNs and trackers that appear in page source but are
# never a link the account holder posted.
_BIO_NOISE = (
    "ogp.me", "opengraphprotocol.org", "schema.org", "w3.org", "purl.org",
    "xmlns.com", "gmpg.org", "fonts.googleapis.com", "fonts.gstatic.com",
    "gstatic.com", "googletagmanager.com", "google-analytics.com",
    "githubassets.com", "gitlab-static.net", "cloudflareinsights.com",
    "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "gravatar.com/avatar",
    # The platform's own media CDNs: avatars and banners, not links the user posted
    "twimg.com", "fbcdn.net", "cdninstagram.com", "tiktokcdn.com", "redditmedia.com",
    "redd.it", "ytimg.com", "ggpht.com", "googleusercontent.com", "licdn.com",
    "githubusercontent.com", "akamaihd.net", "cloudfront.net",
    # Platforms' official onion mirrors, present on every one of their pages
    "twitter3e4tixl4xyajtrzo62zg5vztmjuricljdp2c5kshju4avyoid.onion",
    "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion",
)
_MEDIA_EXT = re.compile(r"\.(?:jpe?g|png|gif|webp|svg|ico|bmp|avif|mp4|webm|css|js|woff2?)(?:[?#].*)?$", re.I)


_SHORTENER_ROOT = re.compile(r"^https?://(?:t\.co|bit\.ly|lnkd\.in|goo\.gl|ow\.ly|buff\.ly)/?$", re.I)


def _is_bio_noise(value: str) -> bool:
    v = value.lower()
    return (any(n in v for n in _BIO_NOISE) or bool(_MEDIA_EXT.search(v))
            or bool(_SHORTENER_ROOT.match(v)))      # "https://t.co" in X's page chrome


def _site_of(url: str) -> str:
    host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _drop_self_links(links: dict, profile_url: str, platform: str) -> dict:
    """A profile page links to its own site everywhere (canonical URL, share
    buttons, the platform's own handle). Those are not links the user posted."""
    own = _site_of(profile_url)
    plat = re.sub(r"[^a-z0-9]", "", (platform or "").lower())
    out = {}
    for key, value in links.items():
        if re.sub(r"[^a-z0-9]", "", key.lower()) == plat:
            continue                              # "devto" handle on Dev.to itself
        if "://" in value or "." in value.split("/")[0]:
            if own and _site_of(value) == own:
                continue                          # dev.to/jack on dev.to, linktr.ee/jack on Linktree
        out[key] = value
    return out


# Site paths that the handle patterns can capture but that are never a user:
# youtube.com/channel/…, twitter.com/intent/…, instagram.com/p/…, github.com/features …
_RESERVED_PATHS = {
    "channel", "watch", "embed", "results", "feed", "playlist", "shorts", "live", "c", "user",
    "intent", "share", "home", "i", "search", "hashtag", "explore", "p", "reel", "reels",
    "stories", "accounts", "about", "login", "signup", "join", "settings", "privacy", "terms",
    "help", "features", "pricing", "sponsors", "orgs", "topics", "trending", "marketplace",
    "enterprise", "security", "notifications", "new", "site", "tos", "legal", "jobs",
    "company", "school", "pub", "in", "tag", "tags", "privacy-policy", "en", "static",
}


def _extract_bio_links(html: str, patterns: dict) -> dict:
    out = {}
    for key, pat in patterns.items():
        for m in re.finditer(pat, html, re.IGNORECASE):
            handle = m.group(1).rstrip("/").strip()
            if key != "website" and handle.lower() in _RESERVED_PATHS:
                continue
            if handle and not _is_bio_noise(handle):
                out[key] = handle
                break
    return out


async def check_platform(session, name: str, platform: dict,
                         username: str, semaphore: asyncio.Semaphore,
                         fast: bool = False) -> dict:
    display_url = platform["url"].replace("{username}", username)
    # check_url: separate probe URL (API endpoint) — falls back to display_url
    probe_url   = platform.get("check_url", platform["url"]).replace("{username}", username)

    result = {
        "platform": name, "url": display_url, "category": platform["category"],
        "color": platform["color"], "found": False, "error": None,
        "confidence": "low", "bio_links": {}, "target_type": "username",
        "source": platform.get("source", "builtin"), "status_code": None, "og_title": "",
        "detection_method": platform.get("method", ""),
    }

    # Skip WAF-only platforms when curl_cffi unavailable
    if platform.get("requires_tls") and not HAS_CURL_CFFI:
        result["error"] = "requires curl_cffi (pip install curl-cffi)"
        return result

    async with semaphore:
        await asyncio.sleep(0.03 + (hash(name) % 15) * 0.01)

        retries = 0 if fast else MAX_RETRIES
        timeout = FAST_TIMEOUT if fast else TIMEOUT
        for attempt in range(retries + 1):
            try:
                if HAS_CURL_CFFI and platform.get("tls_impersonate"):
                    async with CurlSession(impersonate="chrome120") as curl:
                        r   = await curl.get(probe_url, headers=_headers(), timeout=timeout.total,
                                             allow_redirects=True, **netconfig.curl_kwargs())
                        await _apply(result, platform, username, r.status_code, r.text, str(r.url), probe_url)
                else:
                    # Increase read_bufsize to handle large headers (fixes Twitter 8190-byte error)
                    async with session.get(
                        probe_url, headers=_headers(), timeout=timeout,
                        allow_redirects=True, ssl=True,
                        read_bufsize=2**16, **netconfig.request_kwargs(),
                    ) as r:
                        raw_bytes = await netconfig.read_body(r, _MAX_BODY_BYTES)
                        text = raw_bytes.decode("utf-8", errors="ignore")
                        await _apply(result, platform, username, r.status, text, str(r.url), probe_url)
                result["status_code"] = result.get("status_code")
                break

            except asyncio.TimeoutError:
                result["error"] = "timeout"
                if attempt < retries: await asyncio.sleep(1.5 * (attempt + 1))
            except aiohttp.ClientConnectorError:
                result["error"] = "connection_error"; break
            except aiohttp.ClientError as e:
                result["error"] = str(e)[:80]; break
            except KeyboardInterrupt:
                raise
            except Exception as e:
                result["error"] = f"unexpected: {str(e)[:60]}"; break

    return result


def names_user(text: str, username: str) -> bool:
    """The page names this exact user — not just a longer name containing it
    ("Cjacker" or "jackie" on a search page is not "jack")."""
    if not text or not username:
        return False
    pat = r"(?<![A-Za-z0-9])" + re.escape(username) + r"(?![A-Za-z0-9])"
    return re.search(pat, text, re.I) is not None


async def _apply(result: dict, platform: dict, username: str,
                 status: int, text: str, final_url: str, probe_url: str = ""):
    result["final_url"] = final_url
    result["probe_url"] = probe_url or result.get("url", "")

    # WAF detection — catches Cloudflare/bot-check 200s before any method logic
    if text and _is_waf_page(text):
        result["found"]  = False
        result["error"]  = "waf_blocked: bot-check page detected"
        result["confidence"] = "low"
        return

    method = platform["method"]
    result["status_code"] = status

    if method == "status_code":
        result["found"] = status in platform.get("found", [200])
        # A status code alone cannot tell a profile from a catch-all page that
        # answers 200 for any name (forum homepages, sign-in redirects). A real
        # profile page names its user; VK-style login walls opt out.
        if (result["found"] and platform.get("name_in_page", True)
                and not names_user(text, username)):
            result["found"] = False
        if result["found"]: result["confidence"] = "medium"
        # For suspicious WMN status_code-only entries, also read body
        # so the verifier's soft-404 layer can catch false positives
        if result["found"] and platform.get("wmn_soft404_risk") and text:
            from osint.verifier import _has_soft_404_content
            if _has_soft_404_content(text):
                result["found"] = False
                result["error"] = "soft404_body: page body indicates user not found"

    elif method == "text_not_present":
        nf = platform.get("not_found_text", "")
        # Absence of the not-found text alone is weak: a rate-limit page, an
        # error page or changed wording lacks it too. A real profile page
        # names its user, so require that as well.
        result["found"] = ((status == 200) and (nf not in text)
                           and names_user(text, username))
        if result["found"]: result["confidence"] = "medium"

    elif method == "text_present":
        # Replace {username} in found_text pattern
        ft = platform.get("found_text", "").replace("{username}", username)
        result["found"] = (status == 200) and (ft.lower() in text.lower())
        if result["found"]: result["confidence"] = "medium"

    elif method == "response_url":
        err_url = platform.get("error_url", "")
        result["found"] = (status == 200) and (err_url not in final_url)
        if result["found"]: result["confidence"] = "medium"

    elif method == "og_meta":
        og_title = _extract_og_tag(text, "title") or ""
        og_desc  = _extract_og_tag(text, "description") or ""
        nf_list  = platform.get("og_not_found", [])
        f_list   = platform.get("og_found", [])

        if status != 200:
            result["found"] = False
        elif nf_list:
            hit = any(s.lower() in og_title.lower() or s.lower() in og_desc.lower()
                      for s in nf_list)
            result["found"] = not hit and bool(og_title)
        elif f_list:
            # Replace {username} in og_found patterns
            result["found"] = any(
                s.replace("{username}", username).lower() in og_title.lower()
                for s in f_list
            )
        else:
            result["found"] = status == 200

        if result["found"]:
            result["confidence"] = "high"
            if og_title: result["og_title"] = og_title

    # Extract avatar URL from og:image for pHash
    if result["found"] and text:
        og_img = _extract_og_tag(text, "image")
        if og_img and og_img.startswith("http"):
            result["avatar_url"] = og_img

    # Store condensed page text for verifier content-based checks (6000 chars max)
    if text:
        result["_page_text"] = text[:6000]

    # Bio extraction on confirmed profiles
    if result["found"] and platform.get("bio_extract") and text:
        bio_pats = platform.get("bio_patterns", {})
        if bio_pats:
            result["bio_links"] = _drop_self_links(
                _extract_bio_links(text, bio_pats), result.get("url", ""), result["platform"])


CONTROL_ERROR = "unverifiable: platform also reports a random nonexistent username as found"
CONTROL_INCONCLUSIVE = "unverifiable: no clear 'not found' for a random username (blocked, rate-limited or erroring)"
RECHECK_ERROR = "unverifiable: hit did not reproduce on re-check"
CONTROL_RETRY_DELAY = 3.0

# For the random username, these answers say nothing about whether the site
# can tell names apart: rate limits, challenges, gateway and edge errors.
# Every other clear status is the site's answer for an unknown name — usually
# 404, but some sites answer 400, 403, 410 or even 500 ("Interner
# Serverfehler" for unknown users), and that still differs from a profile.
_TRANSIENT_STATUSES = {202, 408, 425, 429, 502, 503, 504, 999} | set(range(520, 531))
_CONTENT_METHODS = ("text_not_present", "text_present", "og_meta", "response_url")


def definitive_negative(control: dict, platform: dict) -> bool:
    """True when a check got a genuine "no such user" answer."""
    if control.get("found") or control.get("error"):
        return False
    status = control.get("status_code")
    if status is None or status in _TRANSIENT_STATUSES:
        return False
    # A 200 is a real negative only where the method read not-found evidence
    # from the page content (not-found text present, profile marker absent).
    return status != 200 or platform.get("method") in _CONTENT_METHODS


def control_username() -> str:
    """A username nobody has: lowercase, starts with a letter, fits common length rules."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "x" + "".join(random.SystemRandom().choice(alphabet) for _ in range(11))


async def _control_probe(session, results: list, plat_map: dict,
                         semaphore: asyncio.Semaphore, username: str) -> list:
    """
    Re-check every hit with a username that cannot exist. A platform that
    "finds" it too returns the same answer for any name — login walls, catch-all
    pages, changed markup — so its hit is evidence of nothing and is discarded.
    Returns the names of the discarded platforms.
    """
    hits = [r for r in results if r.get("found")]
    if not hits:
        return []
    ctrl = control_username()
    while ctrl.lower() == username.lower():
        ctrl = control_username()

    ctrl2 = control_username()
    while ctrl2.lower() in (username.lower(), ctrl.lower()):
        ctrl2 = control_username()

    async def settled(pdef, name, platform):
        """One check, retried once if the answer was transient (429, timeout…)."""
        r = await check_platform(session, platform, pdef, name, semaphore)
        if not r.get("found") and not definitive_negative(r, pdef):
            await asyncio.sleep(CONTROL_RETRY_DELAY)
            r = await check_platform(session, platform, pdef, name, semaphore)
        return r

    async def verify(hit):
        pdef, name = plat_map[hit["platform"]], hit["platform"]
        # Hit and control are fetched together so both answers come from the
        # same moment: a site that served the scan a transient 200 (overload,
        # error page) and a clean 404 a minute later must not "confirm" it.
        control, again = await asyncio.gather(settled(pdef, ctrl, name),
                                              settled(pdef, username, name))
        if control.get("found"):
            return CONTROL_ERROR
        if not definitive_negative(control, pdef):
            return CONTROL_INCONCLUSIVE
        if not again.get("found"):
            return RECHECK_ERROR
        # A second random name must get the same "no such user" answer: a
        # one-off 403/500 under load is not the site's answer for unknown names.
        control2 = await settled(pdef, ctrl2, name)
        if control2.get("found"):
            return CONTROL_ERROR
        if (not definitive_negative(control2, pdef)
                or control2.get("status_code") != control.get("status_code")):
            return CONTROL_INCONCLUSIVE
        # And the hit must hold a third time. A site that answers unknown names
        # at random now has to land "found" three times and "not found" twice
        # in a row to slip through.
        if not (await settled(pdef, username, name)).get("found"):
            return RECHECK_ERROR
        return None

    reasons = await asyncio.gather(*(verify(h) for h in hits))
    discarded = []
    for hit, reason in zip(hits, reasons):
        if reason:
            hit["found"] = False
            hit["error"] = reason
            hit["control_failed"] = True
            discarded.append(hit["platform"])
    return discarded


async def check_username(username: str, platforms: dict = None, progress_cb=None,
                         control: bool = True) -> list:
    plat_map  = platforms or PLATFORMS
    n         = len(plat_map)
    semaphore = asyncio.Semaphore(_dynamic_concurrency(n))
    results   = []
    done      = 0

    connector = netconfig.build_connector(
        limit=_dynamic_concurrency(n), force_close=True, enable_cleanup_closed=True
    )
    async with netconfig.new_session(connector=connector) as session:
        tasks = [
            check_platform(session, name, plat, username, semaphore,
                           fast=n > FAST_SCAN_THRESHOLD)
            for name, plat in plat_map.items()
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            done += 1
            if progress_cb: progress_cb(done, n)
        if control:
            await _control_probe(session, results, plat_map, semaphore, username)
    return results


async def check_email(email: str, progress_cb=None) -> list:
    normalized  = email.strip().lower()
    email_hash  = hashlib.sha256(normalized.encode()).hexdigest()  # #4 SHA256 not MD5
    results     = []

    checks = [{
        "platform": "Gravatar", "category": "other", "color": "#1E8CBE",
        "probe":    f"https://www.gravatar.com/avatar/{email_hash}?d=404",
        "display":  f"https://en.gravatar.com/{email_hash}",
    }]

    connector = netconfig.build_connector(limit=10, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        for i, chk in enumerate(checks):
            r = {
                "platform": chk["platform"], "url": chk["display"],
                "category": chk["category"], "color": chk["color"],
                "found": False, "error": None, "confidence": "high",
                "bio_links": {}, "target_type": "email", "source": "builtin",
            }
            try:
                async with session.get(chk["probe"], headers=_headers(),
                                       timeout=TIMEOUT, ssl=True) as resp:
                    # d=404: 200 = an avatar exists for this address, 404 = none.
                    # Anything else (429, 5xx) says nothing either way.
                    r["found"] = resp.status == 200
                    if resp.status not in (200, 404):
                        r["error"] = f"not checked — HTTP {resp.status}"
            except Exception as e:
                r["error"] = f"not checked — {netconfig.redact(str(e))[:50] or type(e).__name__}"
            results.append(r)
            if progress_cb: progress_cb(i + 1, len(checks))
    return results


def validate_username(u: str):
    if not u: return False, "Username cannot be empty"
    if len(u) > 50: return False, "Username too long (max 50)"
    if not re.match(r'^[a-zA-Z0-9._\-]+$', u):
        return False, "Invalid characters (allowed: a-z 0-9 . _ -)"
    return True, ""

def validate_email(e: str):
    if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', e):
        return True, ""
    return False, "Invalid email format"
