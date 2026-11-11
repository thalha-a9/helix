"""
Helix: small lists that are refreshed once a day.

Two lists ship with Helix and are also published in its repository so a scan
can pick up a newer copy: the sites the daily check switched off, and the
names whose owners asked to be left out. Both are fetched the same way: at
most once a day, through the same proxy as everything else, and never at the
cost of a scan. Any failure leaves the copy at hand in use.
"""

import json
import os
import time
from pathlib import Path
from typing import Callable

from helix_osint import netconfig

DAY = 86_400


async def fetch_daily(url: str, cache: Path, valid: Callable[[object], bool],
                      max_bytes: int = 4 * 1024 * 1024, timeout: float = 8.0) -> bool:
    """Save today's copy of `url` to `cache` when it passes `valid`. True
    when a new copy was saved. Asked for at most once a day, also after a
    failure, so an unreachable list costs one short request a day."""
    import aiohttp
    try:
        if time.time() - cache.stat().st_mtime < DAY:
            return False
    except OSError:
        pass
    saved = False
    try:
        async with netconfig.new_session() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   **netconfig.request_kwargs()) as resp:
                raw = await netconfig.read_body(resp, max_bytes + 1) if resp.status == 200 else b""
        data = json.loads(raw.decode("utf-8")) if raw and len(raw) <= max_bytes else None
        if valid(data):
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data), encoding="utf-8")
            saved = True
    except Exception:
        pass
    if not saved:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            if cache.exists():
                os.utime(cache, None)
            else:
                cache.write_text("{}", encoding="utf-8")
        except OSError:
            pass
    return saved


def read_json(path: Path, valid: Callable[[object], bool], max_bytes: int = 4 * 1024 * 1024):
    """The list in `path` when it is one, else None."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if valid(data) else None
