"""
Helix — Recursive Bio Pivot Engine  (concurrent BFS + verifier pass)
Scans aliases found in bios up to MAX_DEPTH hops.
Each depth level is scanned in full parallel — no sequential waiting.
"""
import asyncio, re
from typing import Dict, List, Set

MAX_DEPTH = 3

_ALIAS_PATTERNS = [
    r"(?:also|find me|follow me|see also|check out)[^\n]{0,60}@([a-zA-Z0-9_\.]{3,40})",
    r"(?:my\s+(?:other|main|alt|backup|dev)\s+(?:account|profile|page))[^\n]{0,30}@([a-zA-Z0-9_\.]{3,40})",
    r"@([a-zA-Z0-9_\.]{3,40})\s+(?:on|for)\s+(?:dev|code|art|music|gaming|business)",
]


def _extract_aliases(bio_links: dict) -> Set[str]:
    aliases = set()
    for handle in bio_links.values():
        h = handle.strip().lstrip("@").lower()
        if 3 <= len(h) <= 40:
            aliases.add(h)
    return aliases


async def pivot_scan(
    root_username:   str,
    initial_results: List[dict],
    platforms:       dict,
    max_depth:       int = MAX_DEPTH,
    progress_cb             = None,
) -> Dict[str, dict]:
    """
    Level-by-level BFS: all aliases at the same depth scan concurrently.
    Each alias result passes through the local verifier before storage.
    """
    from osint.checker   import check_username
    from osint.verifier  import run_local_verifier

    visited:   Set[str] = {root_username.lower()}
    pivot_map: Dict     = {}

    # Seed first level from initial scan
    level: List[tuple] = []   # (username, depth, via_platform)
    for r in initial_results:
        if r.get("found") and r.get("bio_links"):
            for alias in _extract_aliases(r["bio_links"]):
                if alias not in visited:
                    visited.add(alias)
                    level.append((alias, 1, r["platform"]))

    if not level:
        return pivot_map

    print(f"\n  [↻] Pivot: {len(level)} alias(es) queued")

    # ── Level-by-level parallel scan ─────────────────────────────────────────
    while level:
        current_depth = level[0][1]
        current_level = [(u, d, v) for u, d, v in level if d == current_depth]
        level          = [(u, d, v) for u, d, v in level if d != current_depth]

        # Semaphore: max 3 concurrent full scans at once (each scan is already async)
        scan_sem = asyncio.Semaphore(3)

        async def scan_one(username, depth, via):
            async with scan_sem:
                results = await check_username(username, platforms=platforms)
                # ── Verifier pass on pivot results ────────────────────────────
                results, purge_log = run_local_verifier(results, username)
                found = [r for r in results if r.get("found")]
                return username, depth, via, results, found, purge_log

        batch = await asyncio.gather(
            *[scan_one(u, d, v) for u, d, v in current_level]
        )

        for username, depth, via, results, found, purge_log in batch:
            pivot_map[username] = {
                "results":        results,
                "found":          found,
                "depth":          depth,
                "discovered_via": via,
                "purged":         len(purge_log),
            }

            if progress_cb:
                progress_cb(username, depth, len(found))

            # Queue next level from this alias's bio links
            if depth < max_depth:
                for r in found:
                    if r.get("bio_links"):
                        for alias in _extract_aliases(r["bio_links"]):
                            if alias not in visited:
                                visited.add(alias)
                                level.append((alias, depth + 1, r["platform"]))

        await asyncio.sleep(0.3)   # gentle pause between levels

    return pivot_map
