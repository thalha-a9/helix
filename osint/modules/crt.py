"""
Helix — Certificate Transparency Module
Uses crt.sh (free, no key). Single GET request returns JSON.
Finds domains owned by target that never appeared in any bio.
"""
import aiohttp, re
from typing import Dict, List, Set

CRT_URL = "https://crt.sh/"

_GENERIC_SUFFIXES = {
    "amazonaws.com","cloudfront.net","github.io","herokuapp.com",
    "azurewebsites.net","netlify.app","vercel.app","pages.dev",
    "web.app","firebaseapp.com","letsencrypt.org","digicert.com",
    "godaddy.com","namecheap.com","wordpress.com","blogspot.com",
    "wixsite.com","squarespace.com","webflow.io","notion.site",
}


async def _query_crt(session: aiohttp.ClientSession,
                      query: str, timeout: int = 20) -> List[Dict]:
    try:
        async with session.get(
            CRT_URL, params={"q": query, "output": "json"},
            timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
        ) as resp:
            if resp.status != 200: return []
            return await resp.json(content_type=None) or []
    except Exception:
        return []


def _parse(data: List[Dict], username: str) -> Dict:
    domains: Set[str] = set()
    emails:  Set[str] = set()

    for cert in data[:200]:
        # name_value contains newline-separated SANs/CN
        for val in (cert.get("name_value","") + "\n" + cert.get("common_name","")).split("\n"):
            val = val.strip().lstrip("*.")
            if not val: continue
            if "@" in val:
                emails.add(val.lower()); continue
            if "." in val and not val.startswith("@"):
                domains.add(val.lower())

    # Filter out generic CDN/hosting domains
    filtered = {
        d for d in domains
        if not any(d.endswith("." + s) or d == s for s in _GENERIC_SUFFIXES)
    }

    return {
        "domains":     sorted(filtered),
        "emails":      sorted(emails),
        "total_certs": len(data),
    }


async def run(username: str, email: str = None) -> Dict:
    """Query crt.sh by username and email. Returns discovered domains + emails."""
    results = {"by_username": {}, "by_email": {}, "all_domains": set()}

    import asyncio
    connector = aiohttp.TCPConnector(limit=4, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_query_crt(session, f"%{username}%")]
        if email:
            tasks.append(_query_crt(session, email))

        raw = await asyncio.gather(*tasks)

    results["by_username"] = _parse(raw[0], username) if raw[0] else {}
    if email and len(raw) > 1:
        results["by_email"] = _parse(raw[1], username) if raw[1] else {}

    # Merge all unique domains for easy downstream use
    all_d = set(results["by_username"].get("domains",[])) | \
            set(results["by_email"].get("domains",[]))
    results["all_domains"] = sorted(all_d)

    return results
