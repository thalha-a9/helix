"""
Helix — Relationship mapping (issue #23).

Maps who surrounds the subject from what the subject's own accounts *declare*:
employers, organisations, family members and accounts they point to. Nothing
is inferred — no shared surnames, no follower lists, no co-occurrence on a
page. "Not identified" beats a guessed edge.

Declarations are read from the profile's own description (og:description /
meta description, i.e. the bio the account holder wrote) and, for GitHub,
the profile's company field and public organisation memberships.

Edge confidence:
  An edge can never be stronger than the account that declared it — a bio on
  an account that is only a username match (identity LOW) yields a LOW edge.
  Declared by one account          → at most MEDIUM
  Declared by two or more accounts → at most HIGH (independent selectors)
"""

import html as _html
import re
from typing import Dict, List

_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
_GRADE = {v: k for k, v in _ORDER.items()}

_META_DESC = [
    re.compile(r'<meta[^>]+(?:property|name)=["\'](?:og:description|description|twitter:description)["\']'
               r'[^>]+content=["\']([^"\']{3,600})["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']{3,600})["\'][^>]+(?:property|name)='
               r'["\'](?:og:description|description|twitter:description)["\']', re.I),
]

# A target is either an @handle or 1–3 Capitalised words. Deliberately
# case-sensitive: "engineer at heart", "dev at night" are not employers.
_ORG = (r"(?:@([A-Za-z0-9][\w\-]{1,30})|(?:The\s+)?([A-Z0-9][\w&.'\-]*"
        r"(?:(?:\s+(?:of|de|du|la|the))?\s+[A-Z0-9][\w&.'\-]*){0,2}))")
_AT  = r"(?:(?i:at|for|with)\s+|@\s*)"
_ROLE = (r"(?i:(?:software\s+|senior\s+|staff\s+|lead\s+|principal\s+)?"
         r"(?:engineer|developer|dev|designer|manager|intern|researcher|scientist|analyst|"
         r"consultant|architect|director|ceo|cto|coo|cfo|founder|co-founder|cofounder|"
         r"head\s+of\s+\w+|product\s+manager|sre|devops))")
_STUDY = r"(?i:(?:phd\s+|msc\s+|ms\s+|grad(?:uate)?\s+|undergrad(?:uate)?\s+)?student|studying)"

# (relation, target_type, compiled pattern) — the last matched group is the target.
_PATTERNS = [
    ("former_employer", "org", re.compile(
        r"\b(?i:ex-|ex\s+|former(?:ly)?\s+|previously\s+|prev\.?\s+)"
        r"(?:" + _ROLE + r"\s+)?" + _AT + "?" + _ORG)),
    ("employer", "org", re.compile(
        r"\b(?i:works?|working|employed|currently)\s+" + _AT + _ORG)),
    ("education", "org", re.compile(r"\b" + _STUDY + r"\s+" + _AT + _ORG)),
    ("employer", "org", re.compile(r"\b" + _ROLE + r"\s+" + _AT + _ORG)),
    ("organization", "org", re.compile(
        r"\b(?i:member|maintainer|core\s+team|contributor)\s+(?i:of|at)?\s*@?\s*" + _ORG)),
    ("family", "person", re.compile(
        r"\b(?i:(?:my\s+)?(?:wife|husband|partner|spouse|brother|sister|son|daughter|father|"
        r"mother|dad|mom|mum|twin))\b[\s:,\-]*(?i:is\s+|of\s+|to\s+)?@([A-Za-z0-9_.]{2,30})")),
]

_MENTION = re.compile(r"(?<![\w@./])@([A-Za-z0-9_](?:[A-Za-z0-9_.]{0,28}[A-Za-z0-9_])?)\b")

# Words the org pattern can swallow that are never an organisation name.
_STOP = {"the", "a", "an", "my", "our", "home", "night", "heart", "work",
         "large", "least", "most", "best", "scale", "day", "this", "that",
         "and", "or", "of", "in", "on", "i", "me", "you", "it"}


def _bio_from_html(text: str) -> str:
    for pat in _META_DESC:
        m = pat.search(text or "")
        if m:
            return " ".join(_html.unescape(m.group(1)).split())[:500]
    return ""


def annotate_relations(results: List[dict]) -> None:
    """Store the self-written bio of found profiles. Run before _sanitize."""
    for r in results:
        if r.get("found") and r.get("_page_text"):
            bio = _bio_from_html(r["_page_text"])
            if bio:
                r["declared_bio"] = bio


# Employee demonyms → the employer they name ("Ex-Googler").
_DEMONYMS = {"googler": "Google", "xoogler": "Google", "microsoftie": "Microsoft",
             "amazonian": "Amazon", "metamate": "Meta", "facebooker": "Facebook",
             "appler": "Apple", "twitterati": "Twitter"}


def _clean_target(t: str) -> str:
    t = re.split(r"\s*[|·•,;/()\[\]!?]\s*|\s+-\s+|\.\s", t.strip())[0]
    t = t.strip(" .'-@")
    words = t.split()
    while words and words[-1].lower() in _STOP:
        words.pop()
    t = " ".join(words)
    return _DEMONYMS.get(t.lower(), t)


def extract_declarations(bio: str, username: str) -> List[Dict]:
    """[{relation, target, target_type, quote}] declared in one bio."""
    out, taken = [], set()
    user = (username or "").lower()
    for relation, ttype, pat in _PATTERNS:
        for m in pat.finditer(bio or ""):
            target = _clean_target(m.group(m.lastindex))
            key = target.lower()
            if (len(target) < 2 or key in _STOP or key == user
                    or key.lstrip("@") == user or key in taken):
                continue
            taken.add(key)
            if relation == "family":
                target = "@" + target
            out.append({"relation": relation, "target": target, "target_type": ttype,
                        "quote": m.group(0).strip()[:120]})
    for m in _MENTION.finditer(bio or ""):
        handle = m.group(1)
        if handle.lower() in taken or handle.lower() == user:
            continue
        taken.add(handle.lower())
        out.append({"relation": "mentioned", "target": "@" + handle, "target_type": "account",
                    "quote": bio[max(0, m.start() - 30):m.end() + 30].strip()})
    return out


def _key(target: str) -> str:
    return re.sub(r"[^a-z0-9]", "", target.lower())


def build_relationships(results: List[dict], username: str, github_intel: Dict = None) -> List[Dict]:
    """
    Subject-centric edges:
      {relation, target, target_type, confidence, sources:[{platform,url,method,quote,identity}]}
    """
    found = [r for r in results if r.get("found")]
    identity = {r["platform"]: r.get("identity_confidence") or "LOW" for r in found}
    edges: Dict[tuple, Dict] = {}

    def add(relation, target, ttype, platform, url, method, quote):
        k = (relation if relation != "former_employer" else "employer_prev", _key(target))
        if not k[1]:
            return
        e = edges.setdefault(k, {"relation": relation, "target": target,
                                 "target_type": ttype, "sources": []})
        if not any(s["platform"] == platform for s in e["sources"]):
            e["sources"].append({"platform": platform, "url": url, "method": method,
                                 "quote": quote, "identity": identity.get(platform, "LOW")})

    for r in found:
        for d in extract_declarations(r.get("declared_bio") or "", username):
            add(d["relation"], d["target"], d["target_type"], r["platform"], r["url"],
                "declared in profile bio", d["quote"])

    gh = github_intel or {}
    if gh and not gh.get("error") and "GitHub" in identity:
        gh_url = next((r["url"] for r in found if r["platform"] == "GitHub"), "")
        company = (gh.get("company") or "").strip().lstrip("@")
        if company:
            for part in re.split(r"\s*(?:,|/|&| and )\s*", company):
                part = _clean_target(part)
                if len(part) >= 2:
                    add("employer", part, "org", "GitHub", gh_url,
                        "GitHub profile company field", gh.get("company", ""))
        for o in gh.get("orgs") or []:
            if o.get("name"):
                add("organization", o["name"], "org", "GitHub", gh_url,
                    "public GitHub organisation membership", o["name"])

    # An org declared both as employer and as mere membership is one edge.
    for (rel, k), e in list(edges.items()):
        if rel == "organization" and ("employer", k) in edges:
            emp = edges[("employer", k)]
            for s in e["sources"]:
                if not any(x["platform"] == s["platform"] for x in emp["sources"]):
                    emp["sources"].append(s)
            del edges[(rel, k)]

    out = []
    for e in edges.values():
        platforms = {s["platform"] for s in e["sources"]}
        cap = _ORDER["HIGH"] if len(platforms) >= 2 else _ORDER["MEDIUM"]
        best_account = max(_ORDER.get(s["identity"], 0) for s in e["sources"])
        e["confidence"] = _GRADE[min(cap, best_account)]
        out.append(e)
    rank = {"employer": 0, "former_employer": 1, "education": 2, "organization": 3,
            "family": 4, "mentioned": 5}
    out.sort(key=lambda e: (-_ORDER[e["confidence"]], rank.get(e["relation"], 9), e["target"].lower()))
    return out


def edge_line(e: Dict) -> str:
    """Plain-text edge for the console / TXT report."""
    rel = {"employer": "works at", "former_employer": "formerly at",
           "education": "studies at", "organization": "member of", "family": "family",
           "mentioned": "mentions"}.get(e["relation"], e["relation"])
    via = "; ".join(f"{s['platform']} ({s['method']})" for s in e["sources"])
    return f"[{e['confidence']}] subject —{rel}→ {e['target']}   via {via}"
