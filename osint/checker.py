"""
Helix v2.0 — Async Checker Engine
"""

import asyncio
import aiohttp
import hashlib
import re
import random
from typing import Optional
from osint.platforms import PLATFORMS

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

def _extract_bio_links(html: str, patterns: dict) -> dict:
    out = {}
    for key, pat in patterns.items():
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            handle = m.group(1).rstrip("/").strip()
            if handle: out[key] = handle
    return out


async def check_platform(session, name: str, platform: dict,
                         username: str, semaphore: asyncio.Semaphore) -> dict:
    display_url = platform["url"].replace("{username}", username)
    # check_url: separate probe URL (API endpoint) — falls back to display_url
    probe_url   = platform.get("check_url", platform["url"]).replace("{username}", username)

    result = {
        "platform": name, "url": display_url, "category": platform["category"],
        "color": platform["color"], "found": False, "error": None,
        "confidence": "low", "bio_links": {}, "target_type": "username",
        "source": platform.get("source", "builtin"), "status_code": None, "og_title": "",
    }

    # Skip WAF-only platforms when curl_cffi unavailable
    if platform.get("requires_tls") and not HAS_CURL_CFFI:
        result["error"] = "requires curl_cffi (pip install curl-cffi)"
        return result

    async with semaphore:
        await asyncio.sleep(0.03 + (hash(name) % 15) * 0.01)

        for attempt in range(MAX_RETRIES + 1):
            try:
                if HAS_CURL_CFFI and platform.get("tls_impersonate"):
                    async with CurlSession(impersonate="chrome120") as curl:
                        r   = await curl.get(probe_url, headers=_headers(), timeout=14, allow_redirects=True)
                        await _apply(result, platform, username, r.status_code, r.text, str(r.url), probe_url)
                else:
                    # Increase read_bufsize to handle large headers (fixes Twitter 8190-byte error)
                    async with session.get(
                        probe_url, headers=_headers(), timeout=TIMEOUT,
                        allow_redirects=True, ssl=True,
                        read_bufsize=2**16,
                    ) as r:
                        raw_bytes = await r.content.read(_MAX_BODY_BYTES)
                        text = raw_bytes.decode("utf-8", errors="ignore")
                        await _apply(result, platform, username, r.status, text, str(r.url), probe_url)
                result["status_code"] = result.get("status_code")
                break

            except asyncio.TimeoutError:
                result["error"] = "timeout"
                if attempt < MAX_RETRIES: await asyncio.sleep(1.5 * (attempt + 1))
            except aiohttp.ClientConnectorError:
                result["error"] = "connection_error"; break
            except aiohttp.ClientError as e:
                result["error"] = str(e)[:80]; break
            except KeyboardInterrupt:
                raise
            except Exception as e:
                result["error"] = f"unexpected: {str(e)[:60]}"; break

    return result


async def _apply(result: dict, platform: dict, username: str,
                 status: int, text: str, final_url: str, probe_url: str = ""):
    result["final_url"] = final_url

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
        result["found"] = (status == 200) and (nf not in text)
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
            result["bio_links"] = _extract_bio_links(text, bio_pats)


async def check_username(username: str, platforms: dict = None, progress_cb=None) -> list:
    plat_map  = platforms or PLATFORMS
    n         = len(plat_map)
    semaphore = asyncio.Semaphore(_dynamic_concurrency(n))
    results   = []
    done      = 0

    connector = aiohttp.TCPConnector(
        limit=_dynamic_concurrency(n), force_close=True, enable_cleanup_closed=True
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            check_platform(session, name, plat, username, semaphore)
            for name, plat in plat_map.items()
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            done += 1
            if progress_cb: progress_cb(done, n)
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

    connector = aiohttp.TCPConnector(limit=10, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
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
                    r["found"] = resp.status == 200
            except Exception as e:
                r["error"] = str(e)[:60]
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
