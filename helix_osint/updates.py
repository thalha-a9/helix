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
RETRY = 3_600


def _attempt_file(cache: Path) -> Path:
    return cache.with_name(cache.name + ".attempt")


def _last_attempt(cache: Path):
    try:
        data = json.loads(_attempt_file(cache).read_text(encoding="utf-8"))
        return float(data["at"]), bool(data["ok"])
    except (OSError, ValueError, KeyError, TypeError):
        return None, None


async def fetch_daily(url: str, cache: Path, valid: Callable[[object], bool],
                      max_bytes: int = 4 * 1024 * 1024, timeout: float = 8.0) -> bool:
    """Save today's copy of `url` to `cache` when it passes `valid`. True
    when a new copy was saved. A good copy is asked for again after a day.
    A failed download is tried again after an hour, never sooner, so an
    unreachable list costs at most one short request an hour, and a failure
    never stands in for a list: the copy at hand stays as it was."""
    import aiohttp
    try:
        fresh = time.time() - cache.stat().st_mtime < DAY
    except OSError:
        fresh = False
    if fresh and read_json(cache, valid, max_bytes) is not None:
        return False
    at, _ok = _last_attempt(cache)
    if at is not None and time.time() - at < RETRY:
        return False
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
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        _attempt_file(cache).write_text(json.dumps({"at": time.time(), "ok": saved}),
                                        encoding="utf-8")
    except OSError:
        pass
    return saved


def status(cache: Path, valid: Callable[[object], bool]) -> dict:
    """What is known about the downloaded copy: whether there is a good one,
    when it was saved, and when a download was last tried and how it went."""
    from datetime import datetime, timezone

    def utc(t):
        return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds") if t else None
    good = read_json(cache, valid) is not None
    try:
        saved = cache.stat().st_mtime if good else None
    except OSError:
        saved = None
    at, ok = _last_attempt(cache)
    return {"downloaded": good, "saved_utc": utc(saved),
            "last_attempt_utc": utc(at), "last_attempt_ok": ok}


def read_json(path: Path, valid: Callable[[object], bool], max_bytes: int = 4 * 1024 * 1024):
    """The list in `path` when it is one, else None."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if valid(data) else None
