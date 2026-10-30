"""
Helix: Paste Intelligence Module
Source: GitHub Gists (free API).

  gists          public gists of github.com/<username>: only the subject's
                 if that GitHub account is (see identity confidence)

Pastebin text search came from psbdmp.ws, which shut down in 2026, and no
free replacement exists. It is reported as "not checked" with the reason.
A Pastebin *account* with the username is still checked by the Sherlock and
Maigret databases (--sherlock, --maigret, --all).

Every source reports "ok" or "not checked: <reason>" in `status`; an
unreachable source is never presented as "no mentions found".
"""
import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import aiohttp

from osint import netconfig

_HEADERS = {
    "User-Agent": "Helix-OSINT/3.0 (security research)",
    "Accept":     "application/json",
}
_TIMEOUT = aiohttp.ClientTimeout(total=15)

Answer = Tuple[Optional[List[Dict]], str]       # (items, "") or (None, reason)


async def _get_json(session: aiohttp.ClientSession, url: str, headers: dict) -> Tuple[object, str]:
    try:
        async with session.get(url, headers=headers, timeout=_TIMEOUT,
                               **netconfig.request_kwargs()) as resp:
            if resp.status == 404:
                return [], ""
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            return await resp.json(content_type=None), ""
    except asyncio.TimeoutError:
        return None, "timeout"
    except aiohttp.ClientResponseError as e:      # a proxy refusing the CONNECT
        return None, f"HTTP {e.status} {e.message}".strip()[:160]
    except (aiohttp.ClientError, ValueError) as e:
        return None, netconfig.redact(str(e))[:160] or type(e).__name__


async def _gists(session: aiohttp.ClientSession, username: str) -> Answer:
    """Public GitHub Gists for a username."""
    data, err = await _get_json(
        session, f"https://api.github.com/users/{quote(username, safe='')}/gists?per_page=20",
        {**_HEADERS, "Accept": "application/vnd.github.v3+json"})
    if data is None:
        return None, err
    if not isinstance(data, list):
        return None, "unexpected response"
    return [
        {
            "id":          g.get("id", ""),
            "url":         g.get("html_url", ""),
            "description": (g.get("description", "") or "No description")[:100],
            "files":       list((g.get("files") or {}).keys())[:5],
            "date":        (g.get("created_at", "") or "")[:10],
            "source":      "github_gist",
        }
        for g in data[:15] if isinstance(g, dict)
    ], ""


PASTEBIN_GONE = ("no free Pastebin search since psbdmp.ws shut down (2026); "
                 "Pastebin accounts are checked by --sherlock, --maigret and --all")


async def run(username: str, email: str = None) -> Dict:
    """Run paste intelligence for username and optionally email."""
    # username_pastes / email_pastes stay in the result (empty) so reports
    # and saved JSON keep one shape.
    results = {"gists": [], "username_pastes": [], "email_pastes": [], "total": 0, "status": {}}

    connector = netconfig.build_connector(limit=4, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        items, err = await _gists(session, username)

    if items is None:
        results["status"]["gists"] = f"not checked: {err}"
    else:
        results["status"]["gists"] = "ok"
        results["gists"] = items
    results["status"]["pastebin"] = f"not checked: {PASTEBIN_GONE}"
    results["total"] = len(results["gists"])
    return results
