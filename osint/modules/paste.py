"""
Helix — Paste Intelligence Module
Sources: GitHub Gists (free API) + psbdmp.ws (free Pastebin index).

  gists          public gists of github.com/<username> — only the subject's
                 if that GitHub account is (see identity confidence)
  *_mentions     Pastebin pastes whose text mentions the username / email:
                 leads, not the subject's own pastes

Every source reports "ok" or "not checked — <reason>" in `status`; an
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
        return None, f"HTTP {e.status} {e.message}".strip()[:60]
    except (aiohttp.ClientError, ValueError) as e:
        return None, netconfig.redact(str(e))[:60] or type(e).__name__


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


async def _psbdmp(session: aiohttp.ClientSession, query: str) -> Answer:
    """Pastes on psbdmp.ws (Pastebin index) whose text mentions the query."""
    data, err = await _get_json(
        session, f"https://psbdmp.ws/api/v3/search/{quote(query, safe='@')}", _HEADERS)
    if data is None:
        return None, err
    items = data.get("data", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    return [
        {
            "id":     item.get("id", ""),
            "url":    f"https://pastebin.com/{item.get('id', '')}",
            "date":   item.get("time", ""),
            "size":   item.get("size", ""),
            "source": "pastebin",
        }
        for item in items[:10] if isinstance(item, dict) and item.get("id")
    ], ""


async def run(username: str, email: str = None) -> Dict:
    """Run paste intelligence for username and optionally email."""
    results = {"gists": [], "username_pastes": [], "email_pastes": [], "total": 0, "status": {}}
    jobs = {"gists": ("gists", _gists, username),
            "pastebin (username)": ("username_pastes", _psbdmp, username)}
    if email:
        jobs["pastebin (email)"] = ("email_pastes", _psbdmp, email)

    connector = netconfig.build_connector(limit=4, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        answers = await asyncio.gather(*(fn(session, q) for _, fn, q in jobs.values()))

    for (label, (key, _, _)), (items, err) in zip(jobs.items(), answers):
        if items is None:
            results["status"][label] = f"not checked — {err}"
        else:
            results["status"][label] = "ok"
            results[key] = items

    results["total"] = (len(results["gists"]) + len(results["username_pastes"])
                        + len(results["email_pastes"]))
    return results
