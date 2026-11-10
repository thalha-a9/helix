"""
Helix: site sources.

One place that builds the site map a scan runs on: the built-in sites, then
WhatsMyName, Sherlock, Maigret and the fediverse servers, each profile
address kept once. The command line, the daily site check and the Python
API all load their sites through here, so they scan the same list.
"""

import json
import os
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from osint.platform_schema import SEARCH_PROBLEM, filter_valid, profile_key
from osint.platforms import PLATFORMS

SOURCES = ("wmn", "sherlock", "maigret", "fediverse")

# Helix's own list: rules Helix learned itself (helix --learn), one line a
# site. It ships with Helix and wins over the downloaded databases.
SHIPPED_SITES = Path(__file__).parent / "data" / "sites.json"


def own_sites_path() -> Path:
    """Where this user's learned sites are kept (HELIX_SITES overrides it)."""
    return Path(os.environ.get("HELIX_SITES") or Path.home() / ".config" / "helix" / "sites.json")


def read_sites(path) -> Dict[str, dict]:
    """The usable definitions in a site list file; {} when it is missing or
    not a site list. Entries that cannot be scanned soundly are left out."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return filter_valid({k: v for k, v in data.items() if isinstance(v, dict)})[0]


def save_own(name: str, pdef: dict, path=None) -> Path:
    """Add or replace one site in the user's list, one line a site."""
    path = Path(path) if path else own_sites_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data[name] = pdef
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f" {json.dumps(k, ensure_ascii=False)}: {json.dumps(v, ensure_ascii=False)}"
             for k, v in sorted(data.items(), key=lambda kv: kv[0].lower())]
    path.write_text("{\n" + ",\n".join(lines) + "\n}\n", encoding="utf-8")
    return path


def merge(platform_map: Dict[str, dict], loaded: Dict[str, dict]) -> Dict[str, int]:
    """
    Add a database's sites to `platform_map`. Definitions that cannot be
    scanned soundly are dropped, and so are ones whose profile address is
    already listed (the earlier entry, built-in first, is kept).
    Returns the counts: added, repeats, search, malformed.
    """
    usable, unusable = filter_valid(loaded)
    have = {profile_key(v.get("url", "")) for v in platform_map.values()}
    new, repeats = {}, 0
    for k, v in usable.items():
        if k in platform_map:
            continue
        key = profile_key(v.get("url", ""))
        if key in have:
            repeats += 1
            continue
        have.add(key)
        new[k] = v
    platform_map.update(new)
    search = sum(1 for why in unusable.values() if why == [SEARCH_PROBLEM])
    return {"added": len(new), "repeats": repeats, "search": search,
            "malformed": len(unusable) - search}


def merge_note(counts: Dict[str, int]) -> str:
    """'3 malformed entries and 1 already listed', or '' when nothing was skipped."""
    broken, search, repeats = counts["malformed"], counts["search"], counts["repeats"]
    parts = ([f"{broken} malformed entr{'y' if broken == 1 else 'ies'}"] if broken else []) + \
            ([f"{search} search page{'' if search == 1 else 's'}"] if search else []) + \
            ([f"{repeats} already listed"] if repeats else [])
    return " and ".join(parts)


async def load(wmn: bool = False, sherlock: bool = False, maigret: bool = False,
               fediverse: bool = False, nsfw: bool = False, timeout: int = 30,
               builtin: Optional[Dict[str, dict]] = None, own_file=None,
               timeouts: Optional[Dict[str, int]] = None,
               on_start: Optional[Callable[[str], None]] = None,
               on_merged: Optional[Callable[[str, Dict[str, int], int], None]] = None
               ) -> Dict[str, dict]:
    """
    The site map for the chosen sources, built-in sites first.

    on_start(label) is called before a database is fetched and
    on_merged(label, counts, total) after it is added, so a caller can print
    progress; `timeouts` may give a download timeout per source; `builtin`
    replaces the built-in sites (and then nothing else is added to them).

    Order, first listed wins: the user's own learned sites, the built-in
    sites, Helix's own learned list, then the databases.
    """
    timeouts = timeouts or {}

    def merged(label: str, loaded: Dict[str, dict]) -> None:
        counts = merge(platform_map, loaded)
        if on_merged:
            on_merged(label, counts, len(platform_map))

    if builtin is not None:
        platform_map = dict(builtin)
    else:
        own = read_sites(own_file or own_sites_path())
        shipped = read_sites(SHIPPED_SITES)
        if own or shipped:
            platform_map = {}
            if own:
                merged("Your sites", own)
            merge(platform_map, PLATFORMS)
            if shipped:
                merge(platform_map, shipped)
        else:
            platform_map = dict(PLATFORMS)

    if wmn:
        if on_start:
            on_start("Fetching WhatsMyName database...")
        from osint.adapters.wmn_adapter import load_with_fallback as wmn_load
        merged("WhatsMyName", await wmn_load(timeout=timeouts.get("wmn", timeout), include_nsfw=nsfw))
    if sherlock:
        if on_start:
            on_start("Fetching Sherlock database...")
        from osint.adapters.sherlock_adapter import load_with_fallback as sh_load
        merged("Sherlock", await sh_load(timeout=timeouts.get("sherlock", timeout), include_nsfw=nsfw))
    if maigret:
        if on_start:
            on_start("Fetching Maigret database...")
        from osint.adapters.maigret_adapter import load_with_fallback as mg_load
        merged("Maigret", await mg_load(timeout=timeouts.get("maigret", timeout), include_nsfw=nsfw))
    if fediverse:
        from osint.adapters.fediverse_adapter import describe, host_of, load_platforms
        if on_start:
            on_start(f"Loading fediverse servers ({describe()})...")
        known = {host_of(d.get(k, "")) for d in platform_map.values() for k in ("url", "check_url")}
        merged("Fediverse", load_platforms(include_nsfw=nsfw, skip_hosts=known))
    return platform_map


def source_flags(names) -> Tuple[Dict[str, bool], list]:
    """({'wmn': True, ...}, unknown names) for a list such as ['all'] or
    ['sherlock', 'fediverse']; 'builtin' is always included."""
    wanted = {str(n).strip().lower() for n in (names or []) if str(n).strip()}
    unknown = sorted(wanted - set(SOURCES) - {"all", "builtin"})
    return {s: ("all" in wanted or s in wanted) for s in SOURCES}, unknown
