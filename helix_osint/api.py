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

Also here: scan_email() for an address, is_left_out() and refresh_left_out()
to check a name or address before storing it, and record_attempt() and
verify_evidence() for a sealed record of a report (docs/EVIDENCE_SPEC.md).
SCHEMA and the keys above only change in a new major version.
"""

import asyncio
import time
from typing import Dict, Iterable, List, Optional, Tuple, Union

from helix_osint import __version__, evidence, health, leftout, sources as _sources
from helix_osint.checker import (DEFAULT_CONTROLS, check_email, check_username, validate_email,
                                 validate_username)
from helix_osint.confidence import score_identity
from helix_osint.location import annotate_locations
from helix_osint.relationships import annotate_relations
from helix_osint.verifier import run_local_verifier

SCHEMA = "helix.scan.v1"

__all__ = ["SCHEMA", "LeftOut", "__version__", "scan", "scan_sync", "scan_email",
           "scan_email_sync", "is_left_out", "refresh_left_out", "record_attempt",
           "verify_evidence"]


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
    controls = max(DEFAULT_CONTROLS, int(controls or 0))
    raw = await check_username(username, platforms=platform_map, progress_cb=progress_cb,
                               concurrency=concurrency, recover=recover, controls=controls)
    annotate_locations(raw)
    annotate_relations(raw)
    results, _purged = run_local_verifier(_clean(raw), username)
    score_identity(results, username)
    return {
        "schema": SCHEMA,
        "target_type": "username",
        "username": username,
        "controls": controls,
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


def _report(target_type: str, target: str, purpose: str, started: str, t0: float,
            results: list, extra: Dict) -> Dict:
    return {
        "schema": SCHEMA,
        "target_type": target_type,
        target_type: target,
        **extra,
        "purpose": evidence.one_line(purpose) or evidence.PURPOSE_NOT_STATED,
        "started_utc": started,
        "finished_utc": evidence.utc_now(),
        "seconds": round(time.time() - t0, 1),
        "summary": evidence.summarise(results),
        "accounts": [r for r in results if r.get("found")],
        "unconfirmed": [r for r in results if r.get("unconfirmed")],
        "unanswered": [{"platform": r["platform"], "url": r.get("url"), "why": evidence._no_answer(r)}
                       for r in results if not r.get("found") and evidence._no_answer(r)],
        "left_out": [],
        "results": results,
    }


async def scan_email(email: str, holehe: bool = False, nsfw: bool = False, purpose: str = "",
                     progress_cb=None, refresh: bool = True) -> Dict:
    """
    Check one email address, as the command line does with -e: Gravatar, and
    with holehe=True the holehe modules (pip install holehe). Modules that
    would send a password-recovery mail to the address are never run. Same
    report shape and counting rules as scan(), with "email" in place of
    "username". Raises ValueError for a bad address and LeftOut for an
    address on the left-out list.
    """
    email = str(email or "").strip()
    ok, why = validate_email(email)
    if not ok:
        raise ValueError(why)
    if refresh:
        await leftout.refresh()
    if leftout.is_left_out(email):
        raise LeftOut(f"{email} {leftout.REFUSAL}")
    started, t0 = evidence.utc_now(), time.time()
    if holehe:
        from helix_osint.adapters.holehe_adapter import HOLEHE_AVAILABLE, run_holehe
        if not HOLEHE_AVAILABLE:
            raise RuntimeError("holehe is not installed: pip install holehe")
        raw = await run_holehe(email, progress_cb, password_recovery=False, include_nsfw=nsfw)
    else:
        raw = await check_email(email, progress_cb=progress_cb)
    results = _clean([dict(r, target_type="email") for r in raw])
    return _report("email", email, purpose, started, t0, results, {})


def scan_email_sync(email: str, **kwargs) -> Dict:
    """scan_email() for code that is not async."""
    return asyncio.run(scan_email(email, **kwargs))


async def refresh_left_out(timeout: float = 8.0) -> bool:
    """Fetch today's left-out list (at most once a day). False when offline;
    the shipped list and the last download still apply."""
    return await leftout.refresh(timeout=timeout)


def is_left_out(identifier: str) -> bool:
    """True when the owner of this username or email address asked not to be
    looked up. Check before storing or scanning a name. Each call costs a
    deliberate hash (about 0.1 s), so cache the answer for a given name."""
    return leftout.is_left_out(identifier)


def _sites_of(report: Dict) -> Dict[str, dict]:
    return {r["platform"]: {"url": r.get("url", ""), "source": r.get("source", "")}
            for r in report.get("results", []) if r.get("platform")}


def record_attempt(report: Dict, collector: str = "", command: Optional[List[str]] = None
                   ) -> Tuple[Dict, Dict]:
    """
    A sealed record (schema helix.record-attempt.v1, docs/EVIDENCE_SPEC.md)
    of a report from scan() or scan_email(), and the sites it covers.
    Returns (record, sites). Keep both: verify_evidence(record, sites) checks
    later that neither was changed.
    """
    if report.get("schema") != SCHEMA:
        raise ValueError("not a Helix report")
    target_type = report.get("target_type", "username")
    sites = _sites_of(report)
    record = evidence.build(
        username=report.get(target_type, ""), target_type=target_type,
        results=report.get("results", []), platform_map=sites,
        started=report.get("started_utc", ""), finished=report.get("finished_utc", ""),
        wall_seconds=float(report.get("seconds", 0)),
        argv=command or ["helix_osint.api", "scan_email" if target_type == "email" else "scan"],
        concurrency=0, control=target_type == "username",
        controls=report.get("controls") if target_type == "username" else None,
        sites_file="sites.json", purpose=report.get("purpose", ""), collector=collector)
    return record, sites


def verify_evidence(record: Dict, sites: Optional[Dict] = None) -> List[str]:
    """Problems with a sealed record and its sites; [] when both check out."""
    return evidence.verify(record, sites)
