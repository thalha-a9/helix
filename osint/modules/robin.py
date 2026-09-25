"""
Helix — Robin: dark-web lead module (issue #20).

Gives the analysis real data instead of guesses about where to look:

  Ahmia   .onion full-text search through its clearnet front end. Every hit
          must contain the exact search term in its title, description or
          address — Ahmia matches loosely, and a hit that never names the
          subject is not a lead.
  Breach  the subject's confirmed emails against breach databases
          (XposedOrNot, Have I Been Pwned) — see osint/adapters/breachdb.py.

With --ai, the collected results go to the model as numbered sources, and
only statements that cite at least one of those sources are kept. The model
never gets to add a claim that no source supports.

Everything here is lead material. A dark-web page naming a handle is not proof
the subject wrote it, and a breach hit confirms exposure, not identity.
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from osint import netconfig

AHMIA_HOME   = "https://ahmia.fi/"
AHMIA_SEARCH = "https://ahmia.fi/search/"
TIMEOUT      = aiohttp.ClientTimeout(total=30, connect=10)
HEADERS      = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Accept": "text/html,application/xhtml+xml"}
MAX_HITS_PER_TERM = 20

# Markers of a genuine results page with zero hits. Anything else with no
# parsable results (the homepage after a rejected token, a challenge page, a
# redesigned layout) is an error, not "nothing on the dark web".
_EMPTY_STATE = re.compile(r'class=["\'][^"\']*searchResults|no results|0 results|'
                          r"(?:couldn't|could not|did not|didn't) find", re.I)

# Terminal control characters (ANSI escapes etc.) from hostile page text.
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _text(s: str, limit: int) -> str:
    return " ".join(_CTRL.sub(" ", s or "").split())[:limit]


_ONION_RE = re.compile(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b", re.I)


# ── Ahmia HTML parsing ────────────────────────────────────────────────────────

class _FormTokens(HTMLParser):
    """Hidden inputs of the search form — Ahmia rejects searches without them."""

    def __init__(self):
        super().__init__()
        self.in_form = False
        self.tokens: Dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and "/search" in (a.get("action") or ""):
            self.in_form = True
        elif tag == "input" and self.in_form and (a.get("type") or "").lower() == "hidden":
            if a.get("name"):
                self.tokens[a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False


def parse_form_tokens(html: str) -> Dict[str, str]:
    p = _FormTokens()
    p.feed(html or "")
    return p.tokens


class _Results(HTMLParser):
    def __init__(self):
        super().__init__()
        self.results: List[Dict] = []
        self.cur: Optional[Dict] = None
        self.depth = 0
        self.field: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        classes = (a.get("class") or "").split()
        if tag == "li" and "result" in classes:
            self.cur = {"title": "", "description": "", "href": "", "cite": "", "last_seen": ""}
            self.depth = 1
            return
        if self.cur is None:
            return
        if tag == "li":
            self.depth += 1
        if tag == "a" and not self.cur["href"]:
            self.cur["href"] = a.get("href") or ""
            self.field = "title"
        elif tag == "p" and not classes and not self.cur["description"]:
            self.field = "description"
        elif tag == "cite":
            self.field = "cite"
        elif tag == "span" and "lastSeen" in classes:
            ts = a.get("data-timestamp") or ""
            try:
                self.cur["last_seen"] = datetime.fromtimestamp(
                    float(ts), timezone.utc).strftime("%Y-%m-%d")
            except (ValueError, OSError, OverflowError):
                pass

    def handle_endtag(self, tag):
        if self.cur is None:
            return
        if tag in ("a", "p", "cite"):
            self.field = None
        if tag == "li":
            self.depth -= 1
            if self.depth == 0:
                self.results.append(self.cur)
                self.cur = None

    def handle_data(self, data):
        if self.cur is not None and self.field:
            self.cur[self.field] += data


def parse_results(html: str) -> List[Dict]:
    """Ahmia results page → [{title, description, onion, url, last_seen}]."""
    p = _Results()
    p.feed(html or "")
    out = []
    for r in p.results:
        href = r["href"]
        target = parse_qs(urlparse(href).query).get("redirect_url", [""])[0] or href
        m = _ONION_RE.search(target) or _ONION_RE.search(r["cite"])
        if not m:
            continue
        out.append({
            "title":       _text(r["title"], 200),
            "description": _text(r["description"], 400),
            "onion":       m.group(0).lower(),
            "url":         _text(target, 500) if ".onion" in target
                           else f"http://{m.group(0).lower()}/",
            "last_seen":   r["last_seen"],
        })
    return out


def mentions(hit: Dict, term: str) -> bool:
    """The exact term (not a fragment of a longer word) appears in the hit."""
    hay = f"{hit.get('title','')} {hit.get('description','')} {hit.get('url','')}"
    pat = r"(?<![\w.@-])" + re.escape(term) + r"(?![\w@-])"
    return re.search(pat, hay, re.I) is not None


# ── Ahmia search ──────────────────────────────────────────────────────────────

async def ahmia_search(session: aiohttp.ClientSession, term: str) -> Dict:
    """{term, status: ok|error, detail, hits:[...], dropped}"""
    out = {"term": term, "status": "ok", "detail": "", "hits": [], "dropped": 0}
    kw = netconfig.request_kwargs()
    try:
        async with session.get(AHMIA_HOME, headers=HEADERS, timeout=TIMEOUT, **kw) as r:
            tokens = parse_form_tokens(await r.text(errors="replace")) if r.status == 200 else {}
        q = urlencode({"q": term, **tokens})
        async with session.get(f"{AHMIA_SEARCH}?{q}", headers=HEADERS,
                               timeout=TIMEOUT, **kw) as r:
            if r.status != 200:
                out.update(status="error", detail=f"HTTP {r.status}")
                return out
            html = await r.text(errors="replace")
    except asyncio.TimeoutError:
        out.update(status="error", detail="timeout")
        return out
    except aiohttp.ClientResponseError as e:
        # Raised by a proxy refusing the CONNECT; its text embeds the proxy URL.
        out.update(status="error", detail=f"HTTP {e.status} {e.message}".strip()[:80])
        return out
    except aiohttp.ClientError as e:
        out.update(status="error", detail=netconfig.redact(str(e))[:80] or type(e).__name__)
        return out

    raw = parse_results(html)
    if not raw and not _EMPTY_STATE.search(html):
        # Neither results nor Ahmia's empty-state text: we were served
        # something else (a challenge page, a changed layout). Say so rather
        # than report "nothing on the dark web".
        out.update(status="error", detail="unrecognised response page")
        return out

    seen = set()
    for h in raw:
        if not mentions(h, term):
            out["dropped"] += 1
            continue
        if h["url"] in seen:
            continue
        seen.add(h["url"])
        out["hits"].append({**h, "term": term, "source": "Ahmia"})
        if len(out["hits"]) >= MAX_HITS_PER_TERM:
            break
    return out


# ── LLM analysis with enforced attribution ────────────────────────────────────

ANALYST_PROMPT = """You are a dark-web OSINT analyst assisting a licensed investigator.
You are given NUMBERED SOURCES: Ahmia .onion search hits (A#) and breach records (B#).

Rules:
- Every statement must cite the source IDs it rests on, e.g. ["A2","B1"].
- Use only what the sources say. Do not add facts, names, sites or guesses.
- Everything is a lead: a page naming a handle does not prove the subject wrote it;
  a breach record confirms exposure, not identity. Word statements accordingly.
- If the sources support nothing useful, return an empty findings list.

Return ONLY JSON, no markdown:
{"findings":[{"statement":"...","sources":["A1"],"confidence":"LOW|MEDIUM|HIGH"}]}"""


def build_sources(ahmia: List[Dict], breaches: List[Dict]) -> Dict[str, Dict]:
    src: Dict[str, Dict] = {}
    i = 0
    for block in ahmia:
        for h in block["hits"]:
            i += 1
            src[f"A{i}"] = {"type": "ahmia", "term": h["term"], "title": h["title"],
                            "description": h["description"], "onion": h["onion"],
                            "last_seen": h["last_seen"]}
    j = 0
    for v in breaches:
        for b in v["breaches"]:
            j += 1
            src[f"B{j}"] = {"type": "breach", "identifier": v["identifier"], "breach": b["name"],
                            "date": b["date"], "data_classes": b["data_classes"],
                            "via": b["sources"]}
    return src


def validate_findings(raw: str, sources: Dict[str, Dict]) -> Dict:
    """Keep only findings that cite real source IDs; count the rest."""
    text = (raw or "").replace("```json", "").replace("```", "").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        try:
            data = json.loads(m.group(0)) if m else None
        except json.JSONDecodeError:
            data = None
        if data is None:
            return {"findings": [], "rejected": 0, "error": "model did not return JSON"}
    kept, rejected = [], 0
    for f in (data.get("findings") or []) if isinstance(data, dict) else []:
        if not isinstance(f, dict):
            rejected += 1
            continue
        cites = [c for c in (f.get("sources") or []) if isinstance(c, str) and c in sources]
        stmt = str(f.get("statement") or "").strip()
        if not cites or not stmt:
            rejected += 1
            continue
        conf = str(f.get("confidence") or "LOW").upper()
        kept.append({"statement": _text(stmt, 400), "sources": cites,
                     "confidence": conf if conf in ("LOW", "MEDIUM", "HIGH") else "LOW"})
    return {"findings": kept, "rejected": rejected, "error": None}


async def analyse(provider: str, subject: Dict, sources: Dict[str, Dict]) -> Dict:
    if not sources:
        return {"findings": [], "rejected": 0, "error": None, "model": "",
                "skipped": "no sources to analyse"}
    from osint.adapters.ai_verifier import complete
    user = json.dumps({"subject": subject, "sources": sources}, indent=1, default=str)
    out = await complete(provider, ANALYST_PROMPT, user, max_tokens=1500)
    if out.get("error"):
        return {"findings": [], "rejected": 0, "error": out["error"], "model": ""}
    res = validate_findings(out["text"], sources)
    res["model"] = out["model"]
    return res


# ── Entry point ───────────────────────────────────────────────────────────────

async def run(terms: List[str], emails: List[str], ai_provider: str = None,
              breach_verdicts: List[Dict] = None, session: aiohttp.ClientSession = None) -> Dict:
    """
    terms            approved search terms (username, confirmed real name, emails)
    emails           approved emails for the breach sweep
    breach_verdicts  reuse an earlier breach sweep instead of querying again
    """
    clean = []
    for t in terms or []:
        t = (t or "").strip()
        if len(t) >= 3 and t.lower() not in (c.lower() for c in clean):
            clean.append(t)

    own = session is None
    if own:
        session = netconfig.new_session()
    try:
        ahmia = [await ahmia_search(session, t) for t in clean]
        if breach_verdicts is None:
            from osint.adapters.breachdb import check_identifiers
            breach_verdicts = await check_identifiers(emails, session=session)
    finally:
        if own:
            await session.close()

    result = {
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "ahmia":      ahmia,
        "breaches":   breach_verdicts,
        "analysis":   None,
        "note":       "Leads only — verify before relying on any of this.",
    }
    if ai_provider:
        sources = build_sources(ahmia, breach_verdicts)
        result["analysis"] = await analyse(
            ai_provider, {"terms": clean, "emails": emails}, sources)
        result["analysis"]["sources"] = sources
    return result
