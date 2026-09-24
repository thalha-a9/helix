"""
Helix — Maigret engine adapter.

Runs the installed Maigret engine (pip install maigret) as a lead generator.
Maigret's own hits are never trusted: every claimed account is re-fetched by
Helix and handed back to the caller to pass through the local verifier, the
same gate every other finding goes through. Raw Maigret output is lead
material, not evidence.
"""

import asyncio
import difflib
import json
import os
import re
import shutil
import tempfile
from typing import Dict, List, Optional

from osint import netconfig
from osint.checker import (CONTROL_ERROR, _extract_og_tag, _headers, _is_waf_page,
                           _MAX_BODY_BYTES, control_username)

import aiohttp

SOURCE = "maigret_engine"
COLOR  = "#f472b6"

_TAG_CATEGORIES = {
    "coding": "dev", "tech": "dev", "hacking": "dev", "hacker": "dev",
    "gaming": "gaming", "game": "gaming",
    "music": "content", "video": "content", "photo": "content", "art": "content",
    "blog": "content", "streaming": "content",
    "forum": "forum", "q&a": "forum",
    "social": "social", "networking": "social", "dating": "social",
}


def find_maigret() -> Optional[str]:
    return shutil.which("maigret")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def build_command(binary: str, username: str, outdir: str,
                  timeout: int, top_sites: int, proxy: Optional[str]) -> List[str]:
    cmd = [
        binary,
        "--json", "simple", "--folderoutput", outdir,
        "--no-progressbar", "--no-color", "--no-recursion",
        "--timeout", str(timeout), "--top-sites", str(top_sites),
    ]
    if proxy:
        cmd += ["--proxy", proxy]
    # "--" ends option parsing, so a username can never be read as a flag.
    cmd += ["--", username]
    return cmd


def _category(tags: List[str]) -> str:
    for t in tags or []:
        cat = _TAG_CATEGORIES.get(str(t).lower())
        if cat:
            return cat
    return "other"


def parse_report(data: Dict, username: str) -> List[dict]:
    """Turn a Maigret "simple" JSON report into Helix leads (not yet verified)."""
    leads = []
    for site, entry in (data or {}).items():
        if not isinstance(entry, dict) or entry.get("is_similar"):
            continue
        status = entry.get("status") or {}
        if not isinstance(status, dict) or status.get("status") != "Claimed":
            continue
        url = entry.get("url_user") or status.get("url") or ""
        if not url.startswith(("http://", "https://")):
            continue
        leads.append({
            "platform":    site,
            "url":         url,
            "category":    _category(status.get("tags") or []),
            "color":       COLOR,
            "found":       True,
            "error":       None,
            "confidence":  "low",
            "bio_links":   {},
            "target_type": "username",
            "source":      SOURCE,
            "status_code": entry.get("http_status"),
            "og_title":    "",
        })
    return leads


def drop_known(leads: List[dict], known_platforms) -> List[dict]:
    """Helix's own definition wins wherever it already checked the platform."""
    known = {_norm(p) for p in known_platforms}
    return [l for l in leads if _norm(l["platform"]) not in known]


async def _reprobe(session, lead: dict, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        try:
            async with session.get(
                lead["url"], headers=_headers(), allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=14, connect=7),
                **netconfig.request_kwargs(),
            ) as r:
                raw  = await r.content.read(_MAX_BODY_BYTES)
                text = raw.decode("utf-8", errors="ignore")
                lead["status_code"] = r.status
                lead["final_url"]   = str(r.url)
        except Exception as e:
            lead["found"] = False
            lead["error"] = f"reprobe_failed: {str(e)[:60]}"
            return lead

    if lead["status_code"] != 200:
        lead["found"] = False
        lead["error"] = f"reprobe_status: {lead['status_code']}"
        return lead
    if _is_waf_page(text):
        lead["found"] = False
        lead["error"] = "waf_blocked: bot-check page detected"
        return lead

    lead["og_title"]   = _extract_og_tag(text, "title") or ""
    lead["_page_text"] = text[:6000]
    img = _extract_og_tag(text, "image")
    if img and img.startswith("http"):
        lead["avatar_url"] = img
    return lead


def _normalise(text: str, *names: str) -> str:
    for n in names:
        if n:
            text = re.sub(re.escape(n), "{u}", text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text)[:20000]


def looks_same(page_a: str, page_b: str, username: str, control: str,
               threshold: float = 0.9) -> bool:
    """True when two pages are the same page once the usernames are masked out."""
    a, b = _normalise(page_a, username, control), _normalise(page_b, username, control)
    if not a or not b:
        return False
    m = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if m.real_quick_ratio() < threshold or m.quick_ratio() < threshold:
        return False
    return difflib.SequenceMatcher(None, a[:6000], b[:6000], autojunk=False).ratio() >= threshold


async def _control_check(session, lead: dict, username: str, ctrl: str,
                         semaphore: asyncio.Semaphore) -> None:
    """Discard a lead whose URL serves the same page for a name that cannot exist."""
    if username.lower() not in lead["url"].lower():
        return  # ID-based URL — no control URL can be built
    ctrl_url = re.sub(re.escape(username), ctrl, lead["url"], flags=re.IGNORECASE)
    async with semaphore:
        try:
            async with session.get(
                ctrl_url, headers=_headers(), allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=14, connect=7),
                **netconfig.request_kwargs(),
            ) as r:
                status = r.status
                text = (await r.content.read(_MAX_BODY_BYTES)).decode("utf-8", errors="ignore")
        except Exception:
            return
    if status == 200 and looks_same(lead.get("_page_text", ""), text[:6000], username, ctrl):
        lead["found"] = False
        lead["error"] = CONTROL_ERROR
        lead["control_failed"] = True


async def reprobe_leads(leads: List[dict], concurrency: int = 10,
                        username: str = "", control: bool = True) -> List[dict]:
    """Fetch every lead ourselves so the verifier judges real page content."""
    if not leads:
        return []
    semaphore = asyncio.Semaphore(concurrency)
    connector = netconfig.build_connector(limit=concurrency, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        leads = list(await asyncio.gather(*(_reprobe(session, l, semaphore) for l in leads)))
        if control and username:
            ctrl = control_username()
            await asyncio.gather(*(
                _control_check(session, l, username, ctrl, semaphore)
                for l in leads if l.get("found")
            ))
    return leads


def _egress_proxy() -> Optional[str]:
    return (netconfig.get_proxy()
            or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))


async def run_engine(username: str, known_platforms=(), timeout: int = 30,
                     top_sites: int = 500, max_runtime: int = 900,
                     control: bool = True) -> Dict:
    """
    Run Maigret and return re-probed leads for the caller to verify.
    Result: {"results": [...], "leads": int, "skipped_known": int, "error": str|None}
    """
    out = {"results": [], "leads": 0, "skipped_known": 0, "error": None}

    binary = find_maigret()
    if not binary:
        out["error"] = "maigret not installed — pip install maigret"
        return out

    with tempfile.TemporaryDirectory(prefix="helix-maigret-") as tmp:
        cmd = build_command(binary, username, tmp, timeout, top_sites, _egress_proxy())
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, err = await asyncio.wait_for(proc.communicate(), timeout=max_runtime)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                out["error"] = f"maigret exceeded {max_runtime}s and was stopped"
                return out
        except OSError as e:
            out["error"] = f"could not start maigret: {e}"
            return out

        report = os.path.join(tmp, f"report_{username.replace('/', '_')}_simple.json")
        if not os.path.exists(report):
            tail = (err or b"").decode("utf-8", "ignore").strip().splitlines()[-1:] or [""]
            out["error"] = f"maigret produced no report (exit {proc.returncode}) {tail[0][:80]}"
            return out
        try:
            with open(report, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            out["error"] = f"unreadable maigret report: {e}"
            return out

    leads = parse_report(data, username)
    out["leads"] = len(leads)
    fresh = drop_known(leads, known_platforms)
    out["skipped_known"] = len(leads) - len(fresh)
    out["results"] = await reprobe_leads(fresh, username=username, control=control)
    return out
