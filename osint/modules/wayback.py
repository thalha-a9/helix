"""
Helix: Wayback Machine Module
Uses Archive.org CDX API (free, no key).

For each found profile: when it was first and last archived, how many months
have captures, and the bio of the earliest capture (og:title/og:description).
Emails and @handles in that archived bio are listed as clues, leads only: a
username can change hands, so an old capture may be someone else.

Clues come from the archived bio, never the whole page: page source is full
of CSS at-rules (@media, @import) and site-wide addresses (support@...).
A profile whose history could not be fetched is marked "not checked", not
silently treated as never archived.

A profile is looked up under every address it may have been archived at: with
and without a trailing slash, and on the site's old domain (x.com profiles
were archived as twitter.com until 2023). Their captures are merged.
"""
import asyncio
import re
from datetime import datetime
from html import unescape as _unescape
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from osint import netconfig

CDX_API    = "https://web.archive.org/cdx/search/cdx"
WB_BASE    = "https://web.archive.org/web"
_PRIORITY  = {"social", "dev", "forum", "other"}   # looked up first
LIMIT      = 25                                    # profiles per scan: Archive.org is slow and rate limits
_OLD_HOSTS = {"x.com": "twitter.com"}
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


def _rows(data, url: str) -> List[Tuple[str, str]]:
    """CDX JSON (header row, then [timestamp] or [timestamp, original]) -> rows."""
    if not isinstance(data, list) or len(data) < 2:
        return []
    out = []
    for row in data[1:]:
        if row and str(row[0]).isdigit():
            out.append((str(row[0]), str(row[1]) if len(row) > 1 and row[1] else url))
    return out


def history(rows: List[Tuple[str, str]], url: str) -> Optional[Dict]:
    """Merged captures -> first and last capture and the number of archived months.
    The snapshot links use the address that was actually archived."""
    if not rows:
        return None
    rows = sorted(rows)
    first, last = rows[0], rows[-1]
    return {
        "url":         url,
        "first_seen":  _date(first[0]),
        "last_seen":   _date(last[0]),
        "months":      len({stamp[:6] for stamp, _ in rows}),
        "count":       len({stamp[:6] for stamp, _ in rows}),   # archived months (kept for older readers)
        "earliest_url": f"{WB_BASE}/{first[0]}/{first[1]}",
        "latest_url":   f"{WB_BASE}/{last[0]}/{last[1]}",
    }


def parse_cdx(data, url: str) -> Optional[Dict]:
    """CDX JSON for one address -> history, or None."""
    return history(_rows(data, url), url)


def url_variants(url: str) -> List[str]:
    """Addresses a profile may have been archived under."""
    out = [url]
    parts = urlsplit(url)
    if not parts.query:
        out.append(url[:-1] if url.endswith("/") else url + "/")
    host = parts.netloc.lower()
    bare = host[4:] if host.startswith("www.") else host
    if bare in _OLD_HOSTS:
        out.append(urlunsplit((parts.scheme or "https", _OLD_HOSTS[bare],
                               parts.path.rstrip("/"), parts.query, "")))
    return list(dict.fromkeys(out))


def profiles_to_check(found_results: List[Dict]) -> List[Dict]:
    """Found profiles to look up: social, developer and forum sites first."""
    found = [r for r in found_results if r.get("found") and r.get("url")]
    found.sort(key=lambda r: r.get("category") not in _PRIORITY)     # stable
    return found[:LIMIT]


async def _cdx(session: aiohttp.ClientSession, url: str) -> Tuple[Optional[List[Tuple[str, str]]], str]:
    params = {"url": url, "output": "json", "fl": "timestamp,original",
              "filter": "statuscode:200", "collapse": "timestamp:6", "limit": "1000"}
    try:
        async with session.get(CDX_API, params=params, timeout=_TIMEOUT,
                               **netconfig.request_kwargs()) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            return _rows(await resp.json(content_type=None), url), ""
    except asyncio.TimeoutError:
        return None, "timeout"
    except aiohttp.ClientResponseError as e:
        return None, f"HTTP {e.status}"
    except (aiohttp.ClientError, ValueError) as e:
        return None, netconfig.redact(str(e))[:160] or type(e).__name__


def _extract_og(html: str, prop: str) -> str:
    for pat in [
        rf'<meta[^>]+(?:property|name)=["\']og:{re.escape(prop)}["\'][^>]*content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\']og:{re.escape(prop)}["\']',
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return _unescape(m.group(1)).strip()
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
    to_check = profiles_to_check(found_results)
    results: Dict[str, Dict] = {}
    sem = asyncio.Semaphore(2)               # gentle on Archive.org
    connector = netconfig.build_connector(limit=4, force_close=True)

    async with netconfig.new_session(connector=connector, headers=_HEADERS) as session:

        async def process(r):
            url = r["url"]
            rows, errors = [], []
            for variant in url_variants(url):
                async with sem:
                    got, err = await _cdx(session, variant)
                    await asyncio.sleep(0.5)
                if err:
                    errors.append(err)
                else:
                    rows += got
            if errors and not rows:
                results[r["platform"]] = {"url": url, "error": f"not checked: archive.org {errors[0]}"}
                return
            hist = history(rows, url)
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
