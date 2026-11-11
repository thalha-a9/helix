"""
Helix: check yourself (--me).

    helix --me -u yourname
    helix --me -u yourname -e you@example.com

For people who want to see what they have left behind online, not for
investigators. It scans every source for your username, checks your address
against the breach lists when you give one, and for each account found it
shows where that site lets you delete it:

  - the deletion page and how hard it is, from JustDeleteMe
    (justdeleteme.xyz, a community list under the MIT licence);
  - where the list has no entry, a ready erasure request to send to the
    site, naming the laws that give you the right to ask.

It writes one page, <name>_my_accounts.html, that you can keep and work
through. The purpose "my own accounts" is sealed into the evidence when
--record-attempt is used, unless you state another.
"""

import html
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from helix_osint import netconfig

GUIDE_URL = "https://raw.githubusercontent.com/jdm-contrib/jdm/master/_data/sites.json"
GUIDE_NAME = "JustDeleteMe"
_CACHE = Path.home() / ".cache" / "helix" / "delete_guide_v1.json"
_CACHE_TTL = 7 * 86_400
_MAX_BYTES = 8 * 1024 * 1024

PURPOSE = "self-check: my own accounts"

# JustDeleteMe's grades, in plain words.
DIFFICULTY = {
    "easy": "can be deleted from the account settings",
    "medium": "takes a few extra steps",
    "hard": "you have to contact the site",
    "limited": "can only be deleted in part",
    "impossible": "cannot be deleted; ask them to erase your data",
}


def _trim(entry: dict) -> Optional[dict]:
    if not isinstance(entry, dict):
        return None
    url, domains = entry.get("url"), entry.get("domains")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None
    if not isinstance(domains, list):
        return None
    domains = [d.lower().strip(".") for d in domains if isinstance(d, str) and "." in d]
    if not domains:
        return None
    return {"name": str(entry.get("name") or domains[0])[:80], "url": url[:500],
            "difficulty": str(entry.get("difficulty") or "").lower()[:20],
            "notes": " ".join(str(entry.get("notes") or "").split())[:400],
            "email": str(entry.get("email") or "")[:120], "domains": domains}


def _read_cache() -> Optional[List[dict]]:
    try:
        if time.time() - _CACHE.stat().st_mtime < _CACHE_TTL:
            data = json.loads(_CACHE.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else None
    except (OSError, ValueError):
        pass
    return None


async def load_guide(timeout: float = 25.0) -> List[dict]:
    """The deletion guide, trimmed to what Helix shows. [] when it cannot be
    fetched: the scan goes on and every account gets the erasure request."""
    import aiohttp
    cached = _read_cache()
    if cached is not None:
        return cached
    try:
        async with netconfig.new_session() as session:
            async with session.get(GUIDE_URL, timeout=aiohttp.ClientTimeout(total=timeout),
                                   **netconfig.request_kwargs()) as resp:
                if resp.status != 200:
                    return []
                raw = await netconfig.read_body(resp, _MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            return []
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return []
    guide = [e for e in map(_trim, data if isinstance(data, list) else []) if e]
    try:
        _CACHE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE.write_text(json.dumps(guide), encoding="utf-8")
    except OSError:
        pass
    return guide


def index(guide: List[dict]) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for entry in guide:
        for domain in entry["domains"]:
            out.setdefault(domain, entry)
    return out


def find(url: str, by_domain: Dict[str, dict]) -> Optional[dict]:
    """The guide's entry for the site this profile is on: its host, or a
    parent of it (jane.tumblr.com is on tumblr.com)."""
    host = (urlparse(url or "").hostname or "").lower().strip(".")
    parts = host.split(".")
    for i in range(len(parts) - 1):
        entry = by_domain.get(".".join(parts[i:]))
        if entry:
            return entry
    return None


def attach(found: List[dict], guide: List[dict]) -> int:
    """Give each found account its `delete` entry. Returns how many got one."""
    by_domain, n = index(guide), 0
    for r in found:
        entry = find(r.get("url", ""), by_domain)
        if entry:
            r["delete"] = {"url": entry["url"], "difficulty": entry["difficulty"],
                           "notes": entry["notes"], "source": GUIDE_NAME}
            n += 1
    return n


def erasure_request(username: str, accounts: List[dict]) -> str:
    """A request to send to a site that offers no way to delete an account."""
    listed = "\n".join(f"  {r['platform']}: {r['url']}" for r in accounts) or "  (the address of your account)"
    return f"""Subject: Request to erase my account and personal data

Hello,

I hold the account below on your service and I ask you to delete it and to
erase the personal data you hold about me.

  Username: {username}
{listed}

Where the EU or UK General Data Protection Regulation applies to you, this
is a request under Article 17 (right to erasure). Where India's Digital
Personal Data Protection Act, 2023 applies, it is a request under section 12
(right to correction and erasure). Other laws give similar rights; please
treat this as a request under whichever applies.

Please confirm when it is done, or tell me what else you need to confirm
that the account is mine. Do not use this address for anything else.

Thank you,
(your name)

How to use this: send it from the email address the account was opened
with, to the privacy or support address on the site's privacy page. Send
one site its own lines only. Keep a copy and the date. This is a template,
not legal advice.
"""


def _e(text) -> str:
    return html.escape(str(text or ""), quote=True)


def _link(url: str, text: str = "") -> str:
    """A link only for http(s) addresses; anything else is shown as text."""
    if str(url).startswith(("http://", "https://")):
        return f'<a href="{_e(url)}" rel="noopener noreferrer">{_e(text or url)}</a>'
    return _e(text or url)


_CSS = """
:root{--bg:#fff;--fg:#16181d;--dim:#5b6472;--line:#d9dee6;--card:#f5f7fa;--ok:#1a7f37;--warn:#9a6700;--bad:#b42318;--link:#0b5fff}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1115;--fg:#e7eaf0;--dim:#9aa4b2;--line:#2a2f3a;--card:#171a21;--ok:#4ac26b;--warn:#d4a72c;--bad:#ff7b72;--link:#79a8ff}}
:root[data-theme="dark"]{--bg:#0f1115;--fg:#e7eaf0;--dim:#9aa4b2;--line:#2a2f3a;--card:#171a21;--ok:#4ac26b;--warn:#d4a72c;--bad:#ff7b72;--link:#79a8ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:820px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.15rem;margin:32px 0 8px}
p{margin:8px 0}.dim{color:var(--dim)}a{color:var(--link);word-break:break-all}
.acc{border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0;background:var(--card)}
.acc h3{margin:0 0 2px;font-size:1.05rem}.acc p{margin:4px 0}
.tag{display:inline-block;font-size:.8rem;padding:1px 8px;border-radius:999px;border:1px solid var(--line);margin-left:6px}
.easy{color:var(--ok)}.medium,.limited{color:var(--warn)}.hard,.impossible{color:var(--bad)}
pre{white-space:pre-wrap;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;font-size:.9rem;overflow-x:auto}
label{display:block;margin:4px 0}
"""


def page(username: str, email: str, found: List[dict], answered: int, unanswered: int,
         breaches: Optional[List[dict]] = None, when: str = "") -> str:
    """The page to keep: every account with what to do about it."""
    with_link = [r for r in found if r.get("delete")]
    without = [r for r in found if not r.get("delete")]
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<title>My accounts</title>', f"<style>{_CSS}</style></head><body><main>",
           f"<h1>Accounts under {_e(username or email)}</h1>",
           f'<p class="dim">Checked {_e(when)} with Helix. {len(found)} account(s) found on the '
           f"{answered} sites that answered.</p>"]
    if unanswered:
        out.append(f'<p class="dim">{unanswered} more sites gave no clear answer (bot checks, timeouts, '
                   f"rate limits). An account there would not show up here, so this list may not be "
                   f"complete.</p>")
    out.append('<p class="dim">A username can be taken by different people on different sites. '
               "An account listed here is under your name; only you know whether it is yours.</p>")
    if with_link:
        out.append("<h2>Accounts with a known way to delete them</h2>")
        for r in sorted(with_link, key=lambda x: str(x["platform"]).lower()):
            d = r["delete"]
            grade = d.get("difficulty", "")
            out.append('<div class="acc">'
                       f'<h3>{_e(r["platform"])}<span class="tag {_e(grade)}">{_e(grade or "see page")}</span></h3>'
                       f'<p>{_link(r.get("url", ""))}</p>'
                       f'<p>Delete it: {_link(d.get("url", ""))}'
                       + (f' <span class="dim">({_e(DIFFICULTY[grade])})</span>' if grade in DIFFICULTY else "")
                       + "</p>" + (f'<p class="dim">{_e(d["notes"])}</p>' if d.get("notes") else "")
                       + '<label><input type="checkbox"> done</label></div>')
        out.append(f'<p class="dim">Deletion pages and notes come from {GUIDE_NAME} '
                   f"(justdeleteme.xyz), a community list. Sites change; if a link is out of date, "
                   f"look under the account or privacy settings.</p>")
    if without:
        out.append("<h2>Accounts with no deletion page on record</h2>")
        out.append("<p>Look in the account settings first. If there is no delete option, send the "
                   "site the request below.</p>")
        for r in sorted(without, key=lambda x: str(x["platform"]).lower()):
            out.append(f'<div class="acc"><h3>{_e(r["platform"])}</h3><p>{_link(r.get("url", ""))}</p>'
                       f'<label><input type="checkbox"> done</label></div>')
        out.append("<h2>Erasure request</h2>")
        out.append(f"<pre>{_e(erasure_request(username or email, without))}</pre>")
    if not found:
        out.append("<h2>No accounts found</h2><p>None of the sites that answered has an account "
                   "under this name.</p>")
    if breaches is not None:
        out.append("<h2>Leaks</h2>")
        exposed = [v for v in breaches if v.get("exposed")]
        unknown = [v for v in breaches if v.get("exposed") is None]
        if exposed:
            from helix_osint.adapters.breachdb import format_lines
            for v in exposed:
                lines = format_lines(v, limit=30)
                out.append(f'<div class="acc"><h3>{_e(lines[0])}</h3>'
                           + "".join(f'<p class="dim">{_e(line)}</p>' for line in lines[1:]) + "</div>")
            out.append("<p>What to do: change the password on each of these services and anywhere "
                       "you used the same one, and turn on two-step sign-in where it is offered. "
                       "A leak cannot be taken back, but a changed password makes it useless.</p>")
        elif unknown:
            out.append("<p>The breach lists could not be checked this time.</p>")
        else:
            out.append("<p>Your address is not in the breach lists that were checked.</p>")
    out.append('<p class="dim">This page was made on your own computer and holds only what is shown '
               "here. Nothing in it was sent to Helix or anyone else.</p></main></body></html>")
    return "\n".join(out)


def terminal_lines(found: List[dict]) -> List[str]:
    lines = []
    for r in sorted(found, key=lambda x: str(x["platform"]).lower()):
        d = r.get("delete")
        grade = (d or {}).get("difficulty") or ("see page" if d else "no record")
        lines.append(f"[{grade}] {r['platform']}  {r.get('url', '')}")
        if d:
            lines.append(f"    delete: {d['url']}")
    return lines
