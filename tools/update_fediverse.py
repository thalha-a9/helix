"""Rebuild osint/fediverse_servers.py: the fediverse servers --fediverse checks.

    python tools/update_fediverse.py            # about 10 minutes
    python tools/update_fediverse.py --pages 50 # a quicker, smaller list

1. Takes the largest servers from FediDB (api.fedidb.org).
2. Tests each one live: an account that exists there (its admin, or a local
   user from its own directory) must be found, and two made-up usernames must
   get a clean "no such user". Servers that fail either way are dropped.
3. Keeps servers with at least one active user a month: the monthly active
   users FediDB reports, or, for Misskey servers that report none, a public
   local post in the last 30 days.

Run it before a release and commit the regenerated file.
"""
import argparse
import asyncio
import datetime
import json
import os
import random
import string
import sys
import time
import urllib.request

import aiohttp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "osint", "fediverse_servers.py")
UA = {"User-Agent": "helix-osint fediverse list (github.com/thalha-a9/helix)", "Accept": "application/json"}
TIMEOUT = aiohttp.ClientTimeout(total=15, connect=8)

MASTODON_API = {"mastodon", "hometown", "glitch-soc", "glitchsoc", "akkoma", "pleroma", "iceshrimp", "gotosocial"}
MISSKEY = {"misskey", "sharkey", "catodon", "foundkey", "firefish", "cherrypick"}


def fake():
    r = random.SystemRandom()
    return r.choice(string.ascii_lowercase) + "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(11))


def fetch_fedidb(pages):
    url, servers = "https://api.fedidb.org/v1/servers?limit=40", []
    for _ in range(pages):
        req = urllib.request.Request(url, headers={"User-Agent": UA["User-Agent"]})
        data = json.load(urllib.request.urlopen(req, timeout=40))
        for s in data["data"]:
            stats = s.get("stats") or {}
            servers.append({"domain": s["domain"].lower(), "software": (s.get("software") or {}).get("slug"),
                            "mau": stats.get("monthly_active_users")})
        url = (data.get("links") or {}).get("next")
        if not url:
            break
        time.sleep(0.4)
    return servers


async def _get(s, url, method="GET", **kw):
    async with s.request(method, url, headers=UA, timeout=TIMEOUT, **kw) as r:
        try:
            return r.status, json.loads(await r.text())
        except ValueError:
            return r.status, None


async def _known_user(s, d, sw):
    if sw in MASTODON_API:
        for path in ("/api/v2/instance", "/api/v1/instance", "/api/v1/directory?local=true&limit=1"):
            st, j = await _get(s, f"https://{d}{path}")
            if st != 200 or not j:
                continue
            if isinstance(j, list):
                return j[0].get("username") if j else None
            u = ((j.get("contact") or {}).get("account") or {}).get("username") or \
                (j.get("contact_account") or {}).get("username")
            if u:
                return u
    elif sw in MISSKEY:
        st, j = await _get(s, f"https://{d}/api/users", "POST", json={"limit": 1, "origin": "local", "sort": "+follower"})
        return j[0]["username"] if st == 200 and isinstance(j, list) and j else None
    elif sw == "lemmy":
        st, j = await _get(s, f"https://{d}/api/v3/site")
        admins = (j or {}).get("admins") or []
        return admins[0]["person"]["name"] if st == 200 and admins else None
    elif sw == "peertube":
        st, j = await _get(s, f"https://{d}/api/v1/accounts?count=20&sort=-createdAt")
        for a in (j or {}).get("data") or []:
            if a.get("host") == d:
                return a["name"]
    return None


async def _exists(s, d, sw, u):
    """True found, False clean not-found, None unclear."""
    if sw in MASTODON_API:
        st, j = await _get(s, f"https://{d}/api/v1/accounts/lookup?acct={u}")
        if st == 200 and isinstance(j, dict) and str(j.get("username", "")).lower() == u.lower():
            return True
        return False if st == 404 else None
    if sw in MISSKEY:
        st, j = await _get(s, f"https://{d}/api/users/show", "POST", json={"username": u, "host": None})
        if st == 200 and isinstance(j, dict) and str(j.get("username", "")).lower() == u.lower():
            return True
        return False if ((j or {}).get("error") or {}).get("code") == "NO_SUCH_USER" else None
    if sw == "lemmy":
        st, j = await _get(s, f"https://{d}/api/v3/user?username={u}")
        if st == 200 and str((((j or {}).get("person_view") or {}).get("person") or {}).get("name", "")).lower() == u.lower():
            return True
        return False if st in (400, 404) else None
    if sw == "peertube":
        st, j = await _get(s, f"https://{d}/api/v1/accounts/{u}")
        if st == 200 and isinstance(j, dict) and str(j.get("name", "")).lower() == u.lower():
            return True
        return False if st == 404 else None
    return None


async def _misskey_active(s, d):
    cut = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    st, j = await _get(s, f"https://{d}/api/notes/local-timeline", "POST", json={"limit": 1})
    if st == 200 and isinstance(j, list) and j:
        return datetime.datetime.fromisoformat(j[0]["createdAt"].replace("Z", "+00:00")) >= cut
    return False


async def _test(s, sem, srv):
    sw = srv["software"]
    if sw not in MASTODON_API | MISSKEY | {"lemmy", "peertube"}:
        return None
    async with sem:
        try:
            u = await _known_user(s, srv["domain"], sw)
            if not u or await _exists(s, srv["domain"], sw, u) is not True:
                return None
            if any(await _exists(s, srv["domain"], sw, fake()) is not False for _ in range(2)):
                return None
            active = (srv["mau"] or 0) >= 1
            if srv["mau"] is None and sw in MISSKEY:
                active = await _misskey_active(s, srv["domain"])
            return srv if active else None
        except Exception:
            return None


async def test_all(servers):
    sem = asyncio.Semaphore(60)
    async with aiohttp.ClientSession(trust_env=True) as s:
        return [r for r in await asyncio.gather(*(_test(s, sem, x) for x in servers)) if r]


def write_module(kept, path=OUT):
    kept = sorted({(k["domain"], k["software"]) for k in kept})
    lines = [
        '"""Fediverse servers checked by --fediverse (and --all).',
        "",
        "Built by tools/update_fediverse.py; do not edit by hand. Each server",
        "passed a live test on the date below (an existing account found, two",
        "made-up usernames not found) and had at least one active user a month.",
        '"""',
        "",
        f'GENERATED = "{datetime.date.today().isoformat()}"',
        "",
        "SERVERS = (",
    ] + [f"    ({d!r}, {sw!r})," for d, sw in kept] + [")", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return len(kept)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pages", type=int, default=150, help="FediDB pages of 40 servers (default 150)")
    args = ap.parse_args()
    servers = fetch_fedidb(args.pages)
    print(f"FediDB: {len(servers)} servers; testing...", file=sys.stderr)
    kept = asyncio.run(test_all(servers))
    n = write_module(kept)
    print(f"Wrote {n} servers to {os.path.relpath(OUT, ROOT)}", file=sys.stderr)


if __name__ == "__main__":
    main()
