"""
Helix — Paste Intelligence Module
Sources: GitHub Gists (free API) + psbdmp.ws (free Pastebin index).
Note: Pastebin raw scraping requires a pro key — we use psbdmp which indexes
public pastes without authentication.
"""
import asyncio, aiohttp
from typing import Dict, List
from osint import netconfig

_HEADERS = {
    "User-Agent": "Helix-OSINT/3.0 (security research)",
    "Accept":     "application/json",
}


async def _gists(session: aiohttp.ClientSession, username: str) -> List[Dict]:
    """Fetch public GitHub Gists for a username."""
    try:
        async with session.get(
            f"https://api.github.com/users/{username}/gists?per_page=20",
            headers={**_HEADERS, "Accept": "application/vnd.github.v3+json"},
            timeout=aiohttp.ClientTimeout(total=12), ssl=False,
        ) as resp:
            if resp.status != 200: return []
            data = await resp.json()
            return [
                {
                    "id":          g.get("id",""),
                    "url":         g.get("html_url",""),
                    "description": (g.get("description","") or "No description")[:100],
                    "files":       list(g.get("files",{}).keys())[:5],
                    "date":        (g.get("created_at","") or "")[:10],
                    "public":      g.get("public", True),
                    "source":      "github_gist",
                }
                for g in (data or [])[:15]
            ]
    except Exception:
        return []


async def _psbdmp(session: aiohttp.ClientSession, query: str) -> List[Dict]:
    """Search psbdmp.ws (free Pastebin index) for a query term."""
    try:
        async with session.get(
            f"https://psbdmp.ws/api/v3/search/{query}",
            headers=_HEADERS,
            timeout=aiohttp.ClientTimeout(total=15), ssl=False,
        ) as resp:
            if resp.status != 200: return []
            data = await resp.json(content_type=None)
            items = data.get("data",[]) if isinstance(data, dict) else []
            return [
                {
                    "id":     item.get("id",""),
                    "url":    f"https://pastebin.com/{item.get('id','')}",
                    "date":   item.get("time",""),
                    "size":   item.get("size",""),
                    "source": "pastebin",
                }
                for item in items[:10]
            ]
    except Exception:
        return []


async def run(username: str, email: str = None) -> Dict:
    """Run paste intelligence for username and optionally email."""
    results = {
        "gists":          [],
        "username_pastes": [],
        "email_pastes":    [],
        "total":           0,
    }

    connector = netconfig.build_connector(limit=4, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        tasks = [
            _gists(session, username),
            _psbdmp(session, username),
        ]
        if email:
            tasks.append(_psbdmp(session, email))

        raw = await asyncio.gather(*tasks, return_exceptions=True)

    results["gists"]           = raw[0] if not isinstance(raw[0], Exception) else []
    results["username_pastes"] = raw[1] if not isinstance(raw[1], Exception) else []
    if email and len(raw) > 2:
        results["email_pastes"] = raw[2] if not isinstance(raw[2], Exception) else []

    results["total"] = (len(results["gists"]) +
                        len(results["username_pastes"]) +
                        len(results["email_pastes"]))
    return results
