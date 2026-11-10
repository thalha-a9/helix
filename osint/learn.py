"""
Helix: learn a site's rule from its address.

    helix --learn "https://example.com/u/{username}"
    helix --learn "https://example.com/u/{username}" --known alice

Given only where profiles live, Helix works out how the site says "this
account exists" and how it says "no such user":

  1. It asks for made-up names and keeps what the site answers for nobody.
  2. It asks for an account that exists: the one given with --known, or the
     first common name (admin, john, alex ...) the site answers differently.
  3. It compares the two and writes the simplest rule that separates them:
     the HTTP status, where the site redirects to, a "not found" text, or a
     text only a real profile carries.
  4. It runs the rule through the same engine and control probe a scan
     uses: the known account must be found and confirmed, a fresh made-up
     name must get a clear "no such user". A rule that fails is dropped and
     the next kind is tried.

The result is one line of JSON: a complete site definition, with the
account it was learned from kept as `known` so the daily site check can
prove the rule every day.
"""

import asyncio
import json
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from osint import netconfig
from osint.evidence import NO_ANSWER_STATUSES, _no_answer
from osint.platform_schema import problems

TIMEOUT = aiohttp.ClientTimeout(total=20, connect=10)
MAX_BODY = 512 * 1024

# Names tried when no existing account is given. Short, common, and present
# on most sites that have users at all.
COMMON_NAMES = ("admin", "john", "alex", "test", "david", "michael", "anna", "maria",
                "max", "james", "chris", "info", "support", "user", "demo", "root")

# How sites say "no such user", in the languages the databases cover most.
_NOT_FOUND_WORDS = re.compile(
    r"(?i)not\s+found|no\s+such|doesn[’']?t\s+exist|does\s+not\s+exist|not\s+exist|unknown\s+user"
    r"|no\s+user|invalid\s+user|couldn[’']?t\s+find|could\s+not\s+be\s+found|cannot\s+be\s+found"
    r"|isn[’']?t\s+available|not\s+available|404|no\s+longer|page\s+(?:is\s+)?missing|nothing\s+here"
    r"|не\s+найден|не\s+существует|introuvable|n[’']existe\s+pas|nicht\s+gefunden|existiert\s+nicht"
    r"|no\s+encontrad|no\s+existe|não\s+encontrad|não\s+existe|non\s+trovat|non\s+esiste"
    r"|bulunamad|nie\s+znaleziono|nie\s+istnieje|niet\s+gevonden|bestaat\s+niet"
    r"|見つかりません|存在しません|不存在|找不到|찾을\s*수\s*없")


class Sample:
    """One answer of the site: what came back for one name."""

    def __init__(self, name: str, status: Optional[int] = None, final_url: str = "",
                 text: str = "", error: str = ""):
        self.name, self.status, self.final_url, self.text, self.error = name, status, final_url, text, error

    @property
    def clear(self) -> bool:
        """The site answered, as opposed to refusing, limiting or failing."""
        return not self.error and self.status is not None and self.status not in NO_ANSWER_STATUSES

    @property
    def title(self) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", self.text, re.I | re.S)
        return " ".join(m.group(1).split()) if m else ""

    def with_name_out(self, value: str) -> str:
        """`value` with this sample's name replaced by {username}."""
        return re.sub(re.escape(self.name), "{username}", value or "", flags=re.I)

    def describe(self) -> str:
        return self.error or f"HTTP {self.status}"


def site_name(url: str) -> str:
    """A name for the site when none is given: its host, without www."""
    host = (urlparse(url.replace("{username}", "x")).hostname or "site").lower()
    return host[4:] if host.startswith("www.") else host


async def fetch(session, template: str, name: str, headers: Optional[dict] = None) -> Sample:
    from osint.checker import _headers, _is_waf_page
    url = template.replace("{username}", name)
    try:
        async with session.get(url, headers=_headers({"headers": headers} if headers else None),
                               timeout=TIMEOUT, allow_redirects=True, ssl=True, read_bufsize=2 ** 16,
                               **netconfig.request_kwargs()) as r:
            text = (await netconfig.read_body(r, MAX_BODY)).decode("utf-8", errors="ignore")
            if _is_waf_page(text):
                return Sample(name, r.status, str(r.url), text, "bot-check page")
            return Sample(name, r.status, str(r.url), text)
    except asyncio.TimeoutError:
        return Sample(name, error="no reply in time")
    except aiohttp.ClientError as e:
        return Sample(name, error=f"connection failed ({type(e).__name__})")


# Rules, simplest first

def _chunks(text: str) -> List[str]:
    """The pieces of visible text on a page, tags and scripts removed."""
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    out = []
    for piece in re.split(r"<[^>]+>", text):
        piece = " ".join(piece.split())
        if 6 <= len(piece) <= 120:
            out.append(piece)
    return out


def status_rule(pos: List[Sample], neg: List[Sample]) -> Optional[dict]:
    """A real account answers 200, nobody answers something else."""
    from osint.checker import names_user
    if not all(p.status == 200 for p in pos) or any(n.status == 200 for n in neg):
        return None
    rule = {"method": "status_code", "found": [200]}
    if not all(names_user(p.text, p.name) for p in pos):
        rule["name_in_page"] = False        # an API reply that does not repeat the name
    return rule


def redirect_rule(pos: List[Sample], neg: List[Sample]) -> Optional[dict]:
    """Nobody is sent to one fixed address (a 404 or sign-up page)."""
    ends = {n.with_name_out(n.final_url) for n in neg}
    if len(ends) != 1:
        return None
    end = ends.pop()
    if "{username}" in end or any(end in p.final_url for p in pos):
        return None
    return {"method": "response_url", "error_url": end}


def not_found_text_rule(pos: List[Sample], neg: List[Sample]) -> Optional[dict]:
    """A text every "no such user" page shows and a profile does not."""
    from osint.checker import names_user
    if not all(names_user(p.text, p.name) for p in pos):
        return None                          # the engine needs the page to name the user
    candidates: List[str] = []
    titles = {n.with_name_out(n.title) for n in neg}
    if len(titles) == 1:
        title = titles.pop()
        # "User {username} not found": keep the longest part that is the same for everyone.
        candidates += sorted((part.strip() for part in title.split("{username}")), key=len, reverse=True)
    shared = None
    for n in neg:
        here = {c for c in _chunks(n.text) if n.name.lower() not in c.lower()}
        shared = here if shared is None else shared & here
    worded = sorted((c for c in shared or () if _NOT_FOUND_WORDS.search(c)), key=len)
    plain = sorted((c for c in shared or () if not _NOT_FOUND_WORDS.search(c)), key=len, reverse=True)
    candidates += worded + plain[:5]
    texts = []
    for c in candidates:
        if len(c) >= 4 and c not in texts and all(c in n.text for n in neg) \
                and not any(c in p.text for p in pos):
            texts.append(c)
    if not texts:
        return None
    # A text that says "not found" in words beats one that merely differs.
    texts.sort(key=lambda c: 0 if _NOT_FOUND_WORDS.search(c) else 1)
    return {"method": "text_not_present", "not_found_text": texts[0],
            **({"not_found_texts": texts[:3]} if len(texts) > 1 else {})}


def found_text_rule(pos: List[Sample], neg: List[Sample]) -> Optional[dict]:
    """A text around the name that only a real profile carries, such as
    "username":"NAME" in an API reply."""
    first = pos[0]
    best, best_score = None, None
    for m in re.finditer(re.escape(first.name), first.text, re.I):
        window = first.text[max(0, m.start() - 28):m.start()]
        after = first.text[m.end():m.end() + 1]
        # Start the text at a natural edge (a quote, a tag, a brace), never
        # in the middle of a word, so the rule reads like the page does.
        starts = [i for i, ch in enumerate(window) if ch in '"\'<{[@/' or (i and window[i - 1] in " ,>;")]
        for start in starts:
            before = window[start:]
            if "\n" in before or "\n" in after or not before:
                continue
            template = before + "{username}" + after
            in_all = all(template.replace("{username}", p.name).lower() in p.text.lower() for p in pos)
            in_none = not any(template.replace("{username}", n.name).lower() in n.text.lower() for n in neg)
            if not (in_all and in_none):
                continue
            # The shortest text that still holds the field the name sits in
            # ("login":"NAME"): fields further away change without notice.
            keyed = bool(re.search(r'[A-Za-z_]["\']?\s*[:=]\s*["\']?$', before)) or before[-1] in "@/"
            score = (1 if keyed else 0, -len(template))
            if best_score is None or score > best_score:
                best, best_score = template, score
    return {"method": "text_present", "found_text": best} if best else None


RULES = (("the HTTP status", status_rule), ("where the site redirects", redirect_rule),
         ("a 'not found' text", not_found_text_rule), ("a text only a profile carries", found_text_rule))


def explain(pdef: dict) -> str:
    """The learned rule in plain words."""
    method = pdef.get("method")
    if method == "status_code":
        named = "" if pdef.get("name_in_page", True) is False else " and names the user"
        return f"an account exists when the page answers HTTP 200{named}"
    if method == "response_url":
        return f"an account exists when the site does not send you to {pdef['error_url']}"
    if method == "text_not_present":
        return (f"an account exists when the page answers HTTP 200, names the user and does "
                f"not say {pdef['not_found_text']!r}")
    if method == "text_present":
        return f"an account exists when the reply contains {pdef['found_text']!r}"
    return str(method)


# Learning

class Learned:
    def __init__(self):
        self.ok = False
        self.name = ""
        self.pdef: Dict = {}
        self.known = ""
        self.known_given = False
        self.negatives: List[Sample] = []
        self.positives: List[Sample] = []
        self.steps: List[str] = []          # what was tried, in plain words
        self.why = ""                       # why nothing was learned

    def line(self) -> str:
        """The one line to add to a site list."""
        return json.dumps({self.name: self.pdef}, ensure_ascii=False)[1:-1]


def _signature(s: Sample) -> tuple:
    return (s.status, s.with_name_out(s.final_url), s.with_name_out(s.title))


async def _passes(name: str, pdef: dict, known: str) -> str:
    """'' when the rule holds in the real engine, else why not."""
    from osint.checker import check_username, control_username
    hit = (await check_username(known, platforms={name: pdef}))[0]
    if not hit.get("found"):
        return f"{known} was not found by it ({hit.get('error') or 'no match'})"
    nobody = (await check_username(control_username(known), platforms={name: pdef}))[0]
    if nobody.get("found"):
        return "it found a made-up name"
    if _no_answer(nobody):
        return f"a made-up name got no clear answer ({_no_answer(nobody)})"
    return ""


async def learn(url: str, known: Optional[str] = None, name: Optional[str] = None,
                category: str = "other", headers: Optional[dict] = None,
                candidates=COMMON_NAMES) -> Learned:
    """Work out the rule for `url` (a profile address with {username})."""
    from osint.checker import control_username
    out = Learned()
    out.name = name or site_name(url)
    base = {"url": url, "category": category, "color": "#22c55e", "source": "own",
            **({"headers": headers} if headers else {})}
    wrong = problems({**base, "method": "status_code", "found": [200]})
    if wrong:
        out.why = "; ".join(wrong)
        return out

    connector = netconfig.build_connector(limit=4, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        made_up = [control_username(known or ""), control_username(""), control_username(known or "")]
        out.negatives = [await fetch(session, url, n, headers) for n in made_up]
        unclear = [s for s in out.negatives if not s.clear]
        out.steps.append("Made-up names: " + ", ".join(s.describe() for s in out.negatives))
        if unclear:
            out.why = (f"the site gives no clear answer for a made-up name ({unclear[0].describe()}), "
                       f"so nothing it says about a real one can be trusted")
            return out
        if len({_signature(s) for s in out.negatives}) > 1 and len({s.status for s in out.negatives}) > 1:
            out.why = "the site answers made-up names in different ways"
            return out

        tried = [known] if known else list(candidates)
        out.known_given = bool(known)
        nobody = {_signature(s) for s in out.negatives}
        for candidate in tried:
            first = await fetch(session, url, candidate, headers)
            if not first.clear:
                out.steps.append(f"{candidate}: {first.describe()}")
                continue
            if not known and _signature(first) in nobody:
                continue                    # answered like nobody: no such account here
            second = await fetch(session, url, candidate, headers)
            if not second.clear:
                continue
            pos = [first, second]
            out.steps.append(f"Existing account: {candidate} ({'given' if known else 'found by trying common names'}), "
                             f"{first.describe()}")
            # In an API reply the text around the name ("login":"NAME") is the
            # firmer mark; on a page, the site's own "not found" wording is.
            api = first.text.lstrip()[:1] in ("{", "[")
            order = RULES[:2] + (RULES[3], RULES[2]) if api else RULES
            for label, make in order:
                rule = make(pos, out.negatives)
                if not rule:
                    continue
                pdef = {**base, **rule, "known": candidate}
                if problems(pdef):
                    continue
                failed = await _passes(out.name, pdef, candidate)
                if failed:
                    out.steps.append(f"Tried {label}: {failed}")
                    continue
                out.ok, out.pdef, out.known, out.positives = True, pdef, candidate, pos
                out.steps.append(f"Rule: {explain(pdef)}")
                out.steps.append(f"Checked: {candidate} found and confirmed by the control probe, "
                                 f"a fresh made-up name refused")
                return out
            if known:
                break
    if known:
        out.why = (f"no rule separates {known} from a made-up name. Check that the account exists "
                   f"and that the address shows its profile")
    else:
        out.why = ("none of the common names tried has an account the site answers differently. "
                   "Give one that exists with --known")
    return out
