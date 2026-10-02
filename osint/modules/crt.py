"""
Helix — Certificate Transparency Module (crt.sh, free, no key).

What CT logs can soundly say about a subject:

  named_domains  registered domains named exactly after the username
                 (krisnova.net, krisnova.co.uk for "krisnova"). LEADS only:
                 anyone can register a name — live, krisnova.net turned out to
                 belong to an unrelated company.
  email_domains  domains on certificates that list the subject's email
                 address. A much stronger link.

Earlier versions searched "%username%" (substring). crt.sh returns nothing for
that pattern, so the module always reported "no domains"; and a substring
match would have listed strangers' domains (blackjack.com for "jack") anyway.

A crt.sh failure (it is often overloaded: 502, timeouts) is reported as
"not checked", never as "no domains found".
"""
import asyncio
import re
from typing import Dict, List, Optional, Set, Tuple

import aiohttp

from osint import netconfig

CRT_URL = "https://crt.sh/"
TIMEOUT = aiohttp.ClientTimeout(total=60, connect=15)
ATTEMPTS = 3
RETRY_DELAY = 5.0

# Second-level labels under a country code that are part of the public suffix
# (example.co.uk, example.com.mx). Enough to find the registered name without
# a full public-suffix list.
_SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "gob", "or", "ne", "go", "nic"}
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def registered_domain(name: str) -> Optional[str]:
    """'www.krisnova.co.uk' -> 'krisnova.co.uk'; None for anything malformed."""
    labels = name.strip().lstrip("*.").rstrip(".").lower().split(".")
    if len(labels) < 2 or not all(_LABEL.match(l) for l in labels):
        return None
    if (len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _label_of(username: str) -> str:
    return re.sub(r"[^a-z0-9-]", "", (username or "").lower())


async def _query(session: aiohttp.ClientSession, query: str) -> Tuple[Optional[List[Dict]], str]:
    """(certificates, "") or (None, reason). Retries crt.sh's frequent 502s."""
    reason = ""
    for attempt in range(ATTEMPTS):
        if attempt:
            await asyncio.sleep(RETRY_DELAY * attempt)
        try:
            async with session.get(CRT_URL, params={"q": query, "output": "json"},
                                   timeout=TIMEOUT, **netconfig.request_kwargs()) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return (data if isinstance(data, list) else []), ""
                reason = f"HTTP {resp.status}"
        except asyncio.TimeoutError:
            reason = "timeout"
        except (aiohttp.ClientError, ValueError) as e:
            reason = netconfig.redact(str(e))[:60] or type(e).__name__
    return None, reason


def _names(certs: List[Dict]) -> Set[str]:
    out = set()
    for c in certs:
        for v in f"{c.get('name_value', '')}\n{c.get('common_name', '')}".split("\n"):
            v = v.strip().lstrip("*.").lower()
            if v and "@" not in v and "." in v:
                out.add(v)
    return out


def named_after(certs: List[Dict], username: str) -> List[str]:
    """Registered domains whose name is exactly the username."""
    label = _label_of(username)
    found = set()
    for n in _names(certs):
        d = registered_domain(n)
        if d and d.split(".")[0] == label:
            found.add(d)
    return sorted(found)


def on_email_certs(certs: List[Dict], email: str) -> List[str]:
    """Registered domains on certificates that list this exact email."""
    email = (email or "").lower()
    found = set()
    for c in certs:
        blob = f"{c.get('name_value', '')}\n{c.get('common_name', '')}".lower()
        if email not in blob.split():
            continue
        for n in _names([c]):
            d = registered_domain(n)
            if d:
                found.add(d)
    return sorted(found)


async def run(username: str, email: str = None) -> Dict:
    """
    {named_domains, email_domains, all_domains,
     status: {"username": "ok"|"not checked — …"|"skipped — …", "email": …}}
    """
    out = {"named_domains": [], "email_domains": [], "all_domains": [], "status": {}}
    label = _label_of(username)
    jobs = {}
    if len(label) >= 4:
        jobs["username"] = f"{label}.%"
    elif username:
        out["status"]["username"] = "skipped — names under 4 characters match too many domains"
    if email:
        jobs["email"] = email.strip().lower()

    if jobs:
        connector = netconfig.build_connector(limit=4, force_close=True)
        async with netconfig.new_session(connector=connector) as session:
            answers = await asyncio.gather(*(_query(session, q) for q in jobs.values()))
        for (kind, _), (certs, reason) in zip(jobs.items(), answers):
            if certs is None:
                out["status"][kind] = f"not checked — crt.sh {reason}"
                continue
            out["status"][kind] = "ok"
            if kind == "username":
                out["named_domains"] = named_after(certs, username)
            else:
                out["email_domains"] = on_email_certs(certs, email)

    out["all_domains"] = sorted(set(out["named_domains"]) | set(out["email_domains"]))
    return out
