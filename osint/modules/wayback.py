"""
Helix — Wayback Machine Module
Uses Archive.org CDX API (free, no key).
For each found profile: fetches snapshot list + parses earliest archived HTML
to surface old usernames, past email addresses, and bio evolution.
"""
import asyncio, aiohttp, re
from datetime import datetime
from typing import Dict, List, Optional

CDX_API    = "https://web.archive.org/cdx/search/cdx"
WB_BASE    = "https://web.archive.org/web"
_PRIORITY  = {"social","dev","forum","other"}
_HEADERS   = {"User-Agent": "Mozilla/5.0 (compatible; Helix-OSINT/3.0)"}


async def _cdx_snapshots(session: aiohttp.ClientSession,
                          url: str, limit: int = 6) -> List[Dict]:
    params = {
        "url": url, "output": "json", "limit": limit,
        "fl": "timestamp,statuscode,length",
        "filter": "statuscode:200", "collapse": "timestamp:6",
    }
    try:
        async with session.get(CDX_API, params=params,
                               timeout=aiohttp.ClientTimeout(total=15),
                               ssl=False) as resp:
            if resp.status != 200: return []
            data = await resp.json(content_type=None)
            if not data or len(data) < 2: return []
            snaps = []
            for row in data[1:]:
                ts = row[0]
                try:    date = datetime.strptime(ts[:8], "%Y%m%d").strftime("%Y-%m-%d")
                except: date = ts[:8]
                snaps.append({
                    "timestamp":   ts,
                    "date":        date,
                    "wayback_url": f"{WB_BASE}/{ts}/{url}",
                    "size_bytes":  row[2] if len(row) > 2 else "?",
                })
            return snaps
    except Exception:
        return []


def _extract_og(html: str, prop: str) -> str:
    for pat in [
        rf'<meta[^>]+property=["\']og:{re.escape(prop)}["\']\s+content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\']\s+property=["\']og:{re.escape(prop)}["\']',
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m: return m.group(1).strip()
    return ""


async def _fetch_archived_html(session: aiohttp.ClientSession,
                                wayback_url: str) -> str:
    try:
        async with session.get(wayback_url, headers=_HEADERS,
                               timeout=aiohttp.ClientTimeout(total=15),
                               ssl=False, allow_redirects=True) as resp:
            if resp.status == 200:
                return await resp.text(errors="ignore")
    except Exception:
        pass
    return ""


async def check_profiles(found_results: List[Dict]) -> Dict[str, Dict]:
    """
    For each found profile URL: fetch snapshot history + parse earliest archived page.
    Returns {platform: {url, first_seen, last_seen, count, snapshots,
                         archived_title, archived_description}}
    """
    to_check = [r for r in found_results
                if r.get("found") and r.get("category") in _PRIORITY][:20]

    results = {}
    sem     = asyncio.Semaphore(2)   # gentle on Archive.org
    connector = aiohttp.TCPConnector(limit=4, force_close=True)

    async with aiohttp.ClientSession(connector=connector, headers=_HEADERS) as session:

        async def process(r):
            url = r.get("url","")
            if not url: return
            async with sem:
                snaps = await _cdx_snapshots(session, url)
                await asyncio.sleep(0.5)

            if not snaps:
                return

            entry: Dict = {
                "url":        url,
                "first_seen": snaps[0]["date"],
                "last_seen":  snaps[-1]["date"],
                "count":      len(snaps),
                "snapshots":  snaps[:3],
                "archived_title": "",
                "archived_desc":  "",
                "identity_clues": [],
            }

            # Fetch earliest archived HTML to extract historical bio
            async with sem:
                html = await _fetch_archived_html(session, snaps[0]["wayback_url"])
                await asyncio.sleep(0.5)

            if html:
                entry["archived_title"] = _extract_og(html, "title")
                entry["archived_desc"]  = _extract_og(html, "description")

                # Look for email addresses in archived bio
                emails = re.findall(
                    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html)
                for e in emails[:3]:
                    if "noreply" not in e and "example" not in e:
                        entry["identity_clues"].append(f"email: {e}")

                # Look for old usernames / handles in archived bio
                handles = re.findall(r'@([a-zA-Z0-9_\.]{3,40})', html)
                for h in handles[:5]:
                    entry["identity_clues"].append(f"handle: @{h}")

            results[r["platform"]] = entry

        await asyncio.gather(*[process(r) for r in to_check])

    return results
