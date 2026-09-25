"""
Helix — Breach-database coverage (issues #20, #21, #22).

Sweeps a subject's confirmed email addresses against breach-corpus APIs and
returns one verdict per identifier: which breaches, which data classes were
exposed, the date range, and which sources were checked and when.

Metadata only — no credentials, passwords or dump contents are ever fetched.

A breach hit confirms that an identifier was *exposed*; it says nothing about
who owns it. Every finding is a lead for the investigator to adjudicate.

Sources are data (SOURCES below), because breach APIs change and rot:
  xposedornot  free, no key          https://xposedornot.com/api_doc
  hibp         needs HIBP_API_KEY    https://haveibeenpwned.com/API/v3
"""

import asyncio
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import quote

import aiohttp

from osint import netconfig

TIMEOUT = aiohttp.ClientTimeout(total=20, connect=8)
USER_AGENT = "Helix-OSINT (breach metadata lookup)"

SOURCES = [
    {
        "id": "xposedornot",
        "label": "XposedOrNot",
        "kinds": ("email",),
        "url": "https://api.xposedornot.com/v1/breach-analytics?email={q}",
        "key_env": None,
    },
    {
        "id": "hibp",
        "label": "Have I Been Pwned",
        "kinds": ("email",),
        "url": "https://haveibeenpwned.com/api/v3/breachedaccount/{q}?truncateResponse=false",
        "key_env": "HIBP_API_KEY",
    },
]

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _year(date: str) -> Optional[int]:
    m = re.match(r"\s*(\d{4})", str(date or ""))
    return int(m.group(1)) if m else None


# ── Response parsers (pure — unit tested against recorded shapes) ─────────────

def parse_xposedornot(data) -> List[Dict]:
    """breach-analytics → breaches. A null/absent ExposedBreaches means none."""
    if not isinstance(data, dict):
        return []
    exposed = data.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    out = []
    for b in details or []:
        if not isinstance(b, dict) or not b.get("breach"):
            continue
        classes = [c.strip() for c in str(b.get("xposed_data") or "").split(";") if c.strip()]
        out.append({
            "name":         str(b["breach"]),
            "date":         str(b.get("xposed_date") or ""),
            "records":      b.get("xposed_records"),
            "data_classes": classes,
            "domain":       b.get("domain") or "",
            "verified":     str(b.get("verified", "")).lower() in ("yes", "true", "1"),
        })
    return out


def parse_hibp(data) -> List[Dict]:
    """breachedaccount (truncateResponse=false) → breaches."""
    if not isinstance(data, list):
        return []
    out = []
    for b in data:
        if not isinstance(b, dict) or not (b.get("Name") or b.get("Title")):
            continue
        # HIBP flags fabricated and spam-list "breaches" — they are not
        # evidence of a real compromise of the subject's account.
        if b.get("IsFabricated") or b.get("IsSpamList"):
            continue
        out.append({
            "name":         str(b.get("Title") or b.get("Name")),
            "date":         str(b.get("BreachDate") or ""),
            "records":      b.get("PwnCount"),
            "data_classes": [str(c) for c in b.get("DataClasses") or []],
            "domain":       b.get("Domain") or "",
            "verified":     bool(b.get("IsVerified")),
        })
    return out


_PARSERS = {"xposedornot": parse_xposedornot, "hibp": parse_hibp}


# ── Fetch one source ──────────────────────────────────────────────────────────

async def _query(session: aiohttp.ClientSession, src: Dict, identifier: str) -> Dict:
    """Return {"status": ok|error|skipped, "detail": str, "breaches": [...]}."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if src["key_env"]:
        key = os.environ.get(src["key_env"], "").strip()
        if not key:
            return {"status": "skipped", "detail": f"set {src['key_env']} to enable",
                    "breaches": []}
        headers["hibp-api-key"] = key

    url = src["url"].format(q=quote(identifier, safe="@"))
    try:
        async with session.get(url, headers=headers, timeout=TIMEOUT,
                               **netconfig.request_kwargs()) as resp:
            if resp.status == 404:
                # Both APIs answer 404 for "not in any breach".
                return {"status": "ok", "detail": "", "breaches": []}
            if resp.status == 401:
                return {"status": "error", "detail": "API key rejected (401)", "breaches": []}
            if resp.status == 429:
                return {"status": "error", "detail": "rate limited (429)", "breaches": []}
            if resp.status != 200:
                return {"status": "error", "detail": f"HTTP {resp.status}", "breaches": []}
            data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        return {"status": "error", "detail": "timeout", "breaches": []}
    except aiohttp.ClientResponseError as e:
        # Raised by a proxy refusing the CONNECT; its text embeds the proxy URL.
        return {"status": "error", "detail": f"HTTP {e.status} {e.message}".strip()[:80],
                "breaches": []}
    except (aiohttp.ClientError, ValueError) as e:
        return {"status": "error", "detail": netconfig.redact(str(e))[:80] or type(e).__name__,
                "breaches": []}

    return {"status": "ok", "detail": "", "breaches": _PARSERS[src["id"]](data)}


# ── Verdicts ──────────────────────────────────────────────────────────────────

def _merge(per_source: List[Dict]) -> List[Dict]:
    """Merge the same breach reported by several sources into one entry."""
    merged: Dict[str, Dict] = {}
    for src_label, breaches in per_source:
        for b in breaches:
            k = _norm_name(b["name"])
            if k not in merged:
                merged[k] = {**b, "data_classes": list(b["data_classes"]), "sources": []}
            else:
                m = merged[k]
                for c in b["data_classes"]:
                    if c.lower() not in (x.lower() for x in m["data_classes"]):
                        m["data_classes"].append(c)
                if len(b["date"]) > len(m["date"]):   # prefer the fuller date
                    m["date"] = b["date"]
                m["verified"] = m["verified"] or b["verified"]
                if not m.get("records") and b.get("records"):
                    m["records"] = b["records"]
            if src_label not in merged[k]["sources"]:
                merged[k]["sources"].append(src_label)
    return sorted(merged.values(), key=lambda b: (_year(b["date"]) or 0, b["name"]), reverse=True)


def _password_exposed(b: Dict) -> bool:
    return any("password" in c.lower() for c in b["data_classes"])


def summarise(v: Dict) -> str:
    """The plain-language line for the report."""
    ident = v["identifier"]
    ok      = [s["source"] for s in v["sources"] if s["status"] == "ok"]
    not_ok  = [f"{s['source']}: {s['detail']}" for s in v["sources"] if s["status"] != "ok"]
    if v["breaches"]:
        n     = len(v["breaches"])
        years = sorted(y for y in (_year(b["date"]) for b in v["breaches"]) if y)
        span  = ""
        if years:
            span = f" ({years[0]})" if years[0] == years[-1] else f" ({years[0]}–{years[-1]})"
        pw    = sum(1 for b in v["breaches"] if _password_exposed(b))
        line  = f"{ident} appears in {n} breach{'es' if n != 1 else ''}{span}"
        if pw:
            line += f", passwords exposed in {pw}"
        return line + f" — source: {', '.join(ok)}."
    if ok:
        line = f"{ident}: no breaches found in {', '.join(ok)} (checked {v['checked_at']})"
        if not_ok:
            line += f"; not checked — {'; '.join(not_ok)}"
        return line + "."
    return f"{ident}: could not be checked — {'; '.join(not_ok) or 'no source supports this identifier'}."


async def check_identifiers(emails: List[str], session: aiohttp.ClientSession = None) -> List[Dict]:
    """
    One verdict per email:
      {identifier, kind, checked_at, sources:[{source,status,detail,count}],
       breaches:[{name,date,records,data_classes,domain,verified,sources}],
       exposed: bool|None (None = could not be checked), summary}
    """
    idents = []
    for e in emails or []:
        e = (e or "").strip().lower()
        if _EMAIL_RE.match(e) and e not in idents:
            idents.append(e)
    if not idents:
        return []

    own = session is None
    if own:
        session = netconfig.new_session()
    try:
        verdicts = []
        for ident in idents:
            srcs = [s for s in SOURCES if "email" in s["kinds"]]
            answers = await asyncio.gather(*(_query(session, s, ident) for s in srcs))
            sources = [{"source": s["label"], "status": a["status"], "detail": a["detail"],
                        "count": len(a["breaches"])} for s, a in zip(srcs, answers)]
            breaches = _merge([(s["label"], a["breaches"]) for s, a in zip(srcs, answers)
                               if a["status"] == "ok"])
            any_ok = any(a["status"] == "ok" for a in answers)
            v = {
                "identifier": ident,
                "kind":       "email",
                "checked_at": _now(),
                "sources":    sources,
                "breaches":   breaches,
                "exposed":    bool(breaches) if any_ok else None,
                "note":       "Exposure confirms the identifier leaked, not who owns it — a lead to adjudicate.",
            }
            v["summary"] = summarise(v)
            verdicts.append(v)
        return verdicts
    finally:
        if own:
            await session.close()


def format_lines(v: Dict) -> List[str]:
    """Terminal / TXT lines for one verdict."""
    lines = [v["summary"]]
    for b in v["breaches"]:
        extra = []
        if b.get("records"):
            try:
                extra.append(f"{int(b['records']):,} records")
            except (TypeError, ValueError):
                pass
        if b.get("verified"):
            extra.append("verified")
        lines.append(f"  - {b['name']} ({b['date'] or 'date unknown'})"
                     + (f" · {' · '.join(extra)}" if extra else ""))
        if b["data_classes"]:
            lines.append(f"      exposed: {', '.join(b['data_classes'])}")
        lines.append(f"      via: {', '.join(b['sources'])}")
    return lines
