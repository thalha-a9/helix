"""
Helix: fediverse servers (--fediverse, included in --all).

Mastodon, Misskey, Lemmy, PeerTube and compatible servers are separate
websites with their own users: a person on one server is not on the others.
Each server answers a username lookup in the same standard way, so one rule
per software covers all of them:

  Mastodon API   /api/v1/accounts/lookup?acct=NAME   (Mastodon, Akkoma, Pleroma,
                                                     Hometown, Iceshrimp)
  Misskey        the profile page title reads "Display name (@NAME)"
  Lemmy          /api/v3/user?username=NAME
  PeerTube       /api/v1/accounts/NAME

Every server also answers WebFinger, the lookup the fediverse itself uses
when one server looks for an account on another:

  /.well-known/webfinger?resource=acct:NAME@SERVER

It is the fallback rule for each server. Hosting companies rate-limit the
API and the profile pages for a whole network at a time (on 10 Nov 2026 a
full scan got HTTP 403 or 429 from 238 servers this way); WebFinger still
answered, with the account for a real name and 404 for a made-up one.

The server list (helix_osint/fediverse_servers.py) is built and live-tested by
tools/update_fediverse.py. Every hit still goes through the control probe.
"""

import asyncio
import json
import re
from typing import Dict, Iterable, Optional
from urllib.parse import urlparse

from helix_osint.fediverse_servers import GENERATED, SERVERS

MASTODON_API = {"mastodon", "hometown", "glitch-soc", "glitchsoc", "akkoma", "pleroma", "iceshrimp", "gotosocial"}
MISSKEY = {"misskey", "sharkey", "catodon", "foundkey", "firefish", "cherrypick"}

# Adult servers, reviewed by hand from the names of the servers on the list.
# Like adult sites elsewhere, they are only scanned with --nsfw. A name check
# can miss an adult server with an innocent name: report it as an issue.
NSFW = frozenset({
    "adultspace.social", "akkoma.epicboobs.sex", "bara.gallery", "kinktroet.social",
    "kinkycats.org", "lust4love.eu.org", "mastodon-sex.com", "pornanime.club",
    "send.sex", "slutty.city", "social.adultvideo.info", "social.bdsmmo.com",
    "veronaxxx.masto.host", "yiff.life",
})


def webfinger(domain: str, found_text: str) -> Dict:
    """The WebFinger rule for one server. `found_text` is what the reply holds
    for a person's account: Lemmy and PeerTube also answer for communities and
    channels of that name, and those link somewhere else."""
    return {"check_url": f"https://{domain}/.well-known/webfinger?resource=acct:{{username}}@{domain}",
            "method": "text_present", "found_text": found_text}


def platform_for(domain: str, software: str) -> Dict:
    """Helix platform definition for one server, or {} for an unknown software."""
    base = {"category": "social", "source": "fediverse"}
    if software in MASTODON_API:
        return {**base, "url": f"https://{domain}/@{{username}}",
                "check_url": f"https://{domain}/api/v1/accounts/lookup?acct={{username}}",
                "method": "text_present", "found_text": '"username":"{username}"', "color": "#6364ff",
                "fallbacks": [webfinger(domain, "acct:{username}@")]}
    if software in MISSKEY:
        return {**base, "url": f"https://{domain}/@{{username}}",
                "method": "og_meta", "og_found": ["(@{username})"], "color": "#86b300",
                "fallbacks": [webfinger(domain, "acct:{username}@")]}
    if software == "lemmy":
        return {**base, "url": f"https://{domain}/u/{{username}}",
                "check_url": f"https://{domain}/api/v3/user?username={{username}}",
                "method": "text_present", "found_text": '"name":"{username}"', "color": "#00bc8c",
                "fallbacks": [webfinger(domain, '/u/{username}"')]}
    if software == "peertube":
        return {**base, "url": f"https://{domain}/a/{{username}}", "category": "content",
                "check_url": f"https://{domain}/api/v1/accounts/{{username}}",
                "method": "text_present", "found_text": '"name":"{username}"', "color": "#f1680d",
                "fallbacks": [webfinger(domain, '/accounts/{username}"')]}
    return {}


def host_of(url: str) -> str:
    host = urlparse((url or "").replace("{username}", "x")).netloc.lower().split(":")[0]
    return host[4:] if host.startswith("www.") else host


def load_platforms(include_nsfw: bool = False, skip_hosts: Iterable[str] = ()) -> Dict[str, Dict]:
    """{server domain: platform definition}, leaving out servers whose host is
    already covered (another database may list the same server)."""
    skip = {h.lower() for h in skip_hosts}
    out = {}
    for domain, software in SERVERS:
        if domain in skip or (domain in NSFW and not include_nsfw):
            continue
        pdef = platform_for(domain, software)
        if pdef:
            if domain in NSFW:
                pdef["nsfw"] = True
            out[domain] = pdef
    return out


def describe() -> str:
    return f"{len(SERVERS)} servers, list tested {GENERATED}"


# An account that exists on a server, for the live tests

_NAME = re.compile(r"[A-Za-z0-9._\-]{1,50}")


async def _json(session, url: str, method: str = "GET", **kw):
    """(status, parsed JSON or None) for one of a server's public API calls."""
    import aiohttp
    from helix_osint import netconfig
    headers = {"User-Agent": "helix-osint site check (github.com/thalha-a9/helix)",
               "Accept": "application/json"}
    async with session.request(method, url, headers=headers, timeout=aiohttp.ClientTimeout(total=15, connect=8),
                               **netconfig.request_kwargs(), **kw) as r:
        try:
            return r.status, json.loads((await netconfig.read_body(r, 512 * 1024)).decode("utf-8", "ignore"))
        except ValueError:
            return r.status, None


async def known_account(session, domain: str, software: str) -> Optional[str]:
    """
    The name of an account that exists on this server, from the server's own
    public API: its contact or admin account, or a local user from its
    directory. None when the server names nobody. The name comes from a
    stranger's server, so only plain usernames are accepted.
    """
    name = None
    if software in MASTODON_API:
        for path in ("/api/v2/instance", "/api/v1/instance", "/api/v1/directory?local=true&limit=1"):
            st, j = await _json(session, f"https://{domain}{path}")
            if st != 200 or not j:
                continue
            if isinstance(j, list):
                name = j[0].get("username") if j and isinstance(j[0], dict) else None
            elif isinstance(j, dict):
                name = ((j.get("contact") or {}).get("account") or {}).get("username") or \
                    (j.get("contact_account") or {}).get("username")
            if name:
                break
    elif software in MISSKEY:
        st, j = await _json(session, f"https://{domain}/api/users", "POST",
                            json={"limit": 1, "origin": "local", "sort": "+follower"})
        name = j[0].get("username") if st == 200 and isinstance(j, list) and j and isinstance(j[0], dict) else None
    elif software == "lemmy":
        st, j = await _json(session, f"https://{domain}/api/v3/site")
        admins = (j or {}).get("admins") if isinstance(j, dict) else None
        name = admins[0]["person"]["name"] if st == 200 and admins else None
    elif software == "peertube":
        st, j = await _json(session, f"https://{domain}/api/v1/accounts?count=20&sort=-createdAt")
        for a in ((j or {}).get("data") or []) if isinstance(j, dict) else []:
            if a.get("host") == domain:
                name = a.get("name")
                break
    return name if isinstance(name, str) and _NAME.fullmatch(name) else None


async def known_accounts(domains: Iterable[str], concurrency: int = 60, progress_cb=None) -> Dict[str, str]:
    """{server: an account that exists there} for the servers that name one."""
    from helix_osint import netconfig
    software = dict(SERVERS)
    domains = [d for d in domains if d in software]
    out: Dict[str, str] = {}
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def one(session, domain):
        nonlocal done
        async with sem:
            try:
                name = await known_account(session, domain, software[domain])
            except Exception:
                name = None                 # an unreachable or odd server names nobody
        if name:
            out[domain] = name
        done += 1
        if progress_cb:
            progress_cb(done, len(domains))

    connector = netconfig.build_connector(limit=concurrency, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        await asyncio.gather(*(one(session, d) for d in domains))
    return out
