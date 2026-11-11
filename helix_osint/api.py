"""
Helix as a library.

    from helix_osint.api import scan_sync
    report = scan_sync("johndoe", sources="all", purpose="audit agreed with the client")
    for account in report["accounts"]:
        print(account["platform"], account["url"], account["identity_confidence"])

    import asyncio
    from helix_osint.api import scan
    report = asyncio.run(scan("johndoe"))

A library scan is the same scan the command line runs: the same site list,
the control probe on every hit, the local verifier, the identity grades, the
switched-off sites left out and the left-out list honoured. It prints
nothing and returns one dictionary:

  username, purpose, started_utc, finished_utc, seconds
  summary       attempted, answered, found, unanswered and why (the counting
                rules of helix_osint.evidence)
  accounts      the confirmed accounts
  unconfirmed   hits a same-length made-up name contradicted
  unanswered    sites that gave no clear answer, each with the reason
  left_out      sites the daily site check switched off
  results       every site's result
"""

import asyncio
import time
from typing import Dict, Iterable, Optional, Union

from helix_osint import evidence, health, leftout, sources as _sources
from helix_osint.checker import DEFAULT_CONTROLS, check_username, validate_username
from helix_osint.confidence import score_identity
from helix_osint.location import annotate_locations
from helix_osint.relationships import annotate_relations
from helix_osint.verifier import run_local_verifier

SCHEMA = "helix.scan.v1"


class LeftOut(Exception):
    """The name is on the left-out list: its owner asked not to be looked up."""


def _clean(results: list) -> list:
    out = []
    for r in results:
        r = {k: v for k, v in r.items() if not k.startswith("_")}
        r.setdefault("identity_confidence", "")
        r.setdefault("evidence", [])
        out.append(r)
    return out


async def scan(username: str, sources: Union[str, Iterable[str]] = "builtin", nsfw: bool = False,
               controls: int = DEFAULT_CONTROLS, concurrency: Optional[int] = None,
               include_off: bool = False, purpose: str = "", recover: bool = True,
               platforms: Optional[Dict[str, dict]] = None, progress_cb=None) -> Dict:
    """
    Scan one username. `sources` is "builtin", "all", or any of "wmn",
    "sherlock", "maigret", "fediverse" (a list or a comma string).
    `platforms` scans exactly that site map instead. Raises ValueError for a
    name that is not a username and LeftOut for a name on the left-out list.
    """
    username = str(username or "").strip().lstrip("@")
    ok, why = validate_username(username)
    if not ok:
        raise ValueError(why)
    names = sources.split(",") if isinstance(sources, str) else list(sources)
    flags, unknown = _sources.source_flags(names)
    if unknown:
        raise ValueError(f"unknown source(s): {', '.join(unknown)}")
    downloads = any(flags.values()) and platforms is None
    if downloads:
        await leftout.refresh()
    if leftout.is_left_out(username):
        raise LeftOut(f"{username} {leftout.REFUSAL}")

    left_out = []
    if platforms is None:
        platform_map = await _sources.load(nsfw=nsfw, **flags)
        if not include_off:
            if downloads:
                await health.refresh_switched_off()
            platform_map, left_out = health.apply_switched_off(platform_map, health.load_switched_off())
    else:
        platform_map = dict(platforms)

    started, t0 = evidence.utc_now(), time.time()
    raw = await check_username(username, platforms=platform_map, progress_cb=progress_cb,
                               concurrency=concurrency, recover=recover,
                               controls=max(DEFAULT_CONTROLS, int(controls or 0)))
    annotate_locations(raw)
    annotate_relations(raw)
    results, _purged = run_local_verifier(_clean(raw), username)
    score_identity(results, username)
    return {
        "schema": SCHEMA,
        "username": username,
        "purpose": evidence.one_line(purpose) or evidence.PURPOSE_NOT_STATED,
        "started_utc": started,
        "finished_utc": evidence.utc_now(),
        "seconds": round(time.time() - t0, 1),
        "summary": evidence.summarise(results),
        "accounts": [r for r in results if r.get("found")],
        "unconfirmed": [r for r in results if r.get("unconfirmed")],
        "unanswered": [{"platform": r["platform"], "url": r.get("url"), "why": evidence._no_answer(r)}
                       for r in results if not r.get("found") and evidence._no_answer(r)],
        "left_out": left_out,
        "results": results,
    }


def scan_sync(username: str, **kwargs) -> Dict:
    """scan() for code that is not async."""
    return asyncio.run(scan(username, **kwargs))
