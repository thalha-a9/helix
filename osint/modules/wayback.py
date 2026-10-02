"""
Helix — Wayback Machine Module
Uses Archive.org CDX API (free, no key).

For each found profile: when it was first and last archived, how many months
have captures, and the bio of the earliest capture (og:title/og:description).
Emails and @handles in that archived bio are listed as clues — leads only: a
username can change hands, so an old capture may be someone else.

Clues come from the archived bio, never the whole page: page source is full
of CSS at-rules (@media, @import) and site-wide addresses (support@…).
A profile whose history could not be fetched is marked "not checked", not
silently treated as never archived.
"""
import asyncio
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import aiohttp

from osint import netconfig

CDX_API    = "https://web.archive.org/cdx/search/cdx"
WB_BASE    = "https://web.archive.org/web"
_PRIORITY  = {"social", "dev", "forum", "other"}
_HEADERS   = {"User-Agent": "Mozilla/5.0 (compatible; Helix-OSINT/3.0)"}
_TIMEOUT   = aiohttp.ClientTimeout(total=30)

_EMAIL     = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_HANDLE    = re.compile(r"(?<![\w.@])@([a-zA-Z0-9_](?:[a-zA-Z0-9_.]{1,38}[a-zA-Z0-9_])?)")
_CSS_AT    = {"media", "import", "font-face", "font", "webkit", "moz", "keyframes", "charset", "supports", "page",
              "namespace", "layer", "container", "property"}


def _date(ts: str) -> str:
    try:
        return datetime.strptime(ts[:8], "%Y%m%d").strftime("%Y-%m-%d")
    except ValueError:
        return ts[:8]


def parse_cdx(data, url: str) -> Optional[Dict]:
    """CDX JSON (header row + one row per archived month) -> history, or None."""
    if not isinstance(data, list) or len(data) < 2:
        return None
    stamps = sorted(row[0] for row in data[1:] if row and str(row[0]).isdigit())
    if not stamps:
        return None
    return {
        "url":         url,
        "first_seen":  _date(stamps[0]),
        "last_seen":   _date(stamps[-1]),
        "months":      len(stamps),
        "count":       len(stamps),          # archived months (kept for older readers)
        "earliest_url": f"{WB_BASE}/{stamps[0]}/{url}",
        "latest_url":   f"{WB_BASE}/{stamps[-1]}/{url}",
    }


async def _cdx(session: aiohttp.ClientSession, url: str) -> Tuple[Optional[Dict], str]:
    params = {"url": url, "output": "json", "fl": "timestamp",
              "filter": "statuscode:200", "collapse": "timestamp:6", "limit": "1000"}
    try:
        async with session.get(CDX_API, params=params, timeout=_TIMEOUT,
                               **netconfig.request_kwargs()) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            return parse_cdx(await resp.json(content_type=None), url), ""
    except asyncio.TimeoutError:
        return None, "timeout"
    except aiohttp.ClientResponseError as e:
        return None, f"HTTP {e.status}"
    except (aiohttp.ClientError, ValueError) as e:
        return None, netconfig.redact(str(e))[:60] or type(e).__name__


def _extract_og(html: str, prop: str) -> str:
    for pat in [
        rf'<meta[^>]+(?:property|name)=["\']og:{re.escape(prop)}["\'][^>]*content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\']og:{re.escape(prop)}["\']',
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def bio_clues(title: str, desc: str, username: str = "") -> List[str]:
    """Emails and @handles written in an archived bio."""
    text = f"{title}\n{desc}"
    clues = []
    for e in _EMAIL.findall(text):
        if "noreply" not in e.lower() and "example." not in e.lower():
            clues.append(f"email: {e}")
    for h in _HANDLE.findall(text):
        if h.lower() in _CSS_AT or h.lower() == (username or "").lower():
            continue
        clues.append(f"handle: @{h}")
    return list(dict.fromkeys(clues))[:6]


async def _archived_html(session: aiohttp.ClientSession, wayback_url: str) -> str:
    try:
        async with session.get(wayback_url, headers=_HEADERS, timeout=_TIMEOUT,
                               allow_redirects=True, **netconfig.request_kwargs()) as resp:
            if resp.status == 200:
                return (await netconfig.read_body(resp, 512 * 1024)).decode("utf-8", errors="ignore")
    except (asyncio.TimeoutError, aiohttp.ClientError):
        pass
    return ""


async def check_profiles(found_results: List[Dict], username: str = "") -> Dict[str, Dict]:
    """
    {platform: {url, first_seen, last_seen, months, archived_title, archived_desc,
                identity_clues}}            for archived profiles
    {platform: {url, error}}                where the history could not be fetched
    Profiles never archived are left out.
    """
    to_check = [r for r in found_results
                if r.get("found") and r.get("category") in _PRIORITY][:20]
    results: Dict[str, Dict] = {}
    sem = asyncio.Semaphore(2)               # gentle on Archive.org
    connector = netconfig.build_connector(limit=4, force_close=True)

    async with netconfig.new_session(connector=connector, headers=_HEADERS) as session:

        async def process(r):
            url = r.get("url", "")
            if not url:
                return
            async with sem:
                hist, err = await _cdx(session, url)
                await asyncio.sleep(0.5)
            if err:
                results[r["platform"]] = {"url": url, "error": f"not checked — archive.org {err}"}
                return
            if not hist:
                return
            async with sem:
                html = await _archived_html(session, hist["earliest_url"])
                await asyncio.sleep(0.5)
            title = _extract_og(html, "title") if html else ""
            desc = _extract_og(html, "description") if html else ""
            results[r["platform"]] = {**hist, "archived_title": title, "archived_desc": desc,
                                      "identity_clues": bio_clues(title, desc, username)}

        await asyncio.gather(*[process(r) for r in to_check])

    return results
