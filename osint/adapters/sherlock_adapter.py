"""
Helix — Sherlock Adapter  (with 24-hour local cache)
Cache: ~/.cache/helix/sherlock_data.json — avoids re-downloading on every run.
"""
import aiohttp, json, time
from pathlib import Path
from typing import Dict, Optional

# Multiple fallback URLs — Sherlock relocated data.json across releases
SHERLOCK_URLS = [
    # Current location (sherlock >= 0.16.0 - renamed to sherlock_project)
    "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
    # Previous location (sherlock 0.15.x)
    "https://raw.githubusercontent.com/sherlock-project/sherlock/main/sherlock/resources/data.json",
    # Legacy
    "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock/resources/data.json",
]
SHERLOCK_URL = SHERLOCK_URLS[0]  # kept for backward compat
_CACHE_DIR  = Path.home() / ".cache" / "helix"
_CACHE_FILE = _CACHE_DIR / "sherlock_data.json"
_CACHE_TTL  = 86_400   # 24 hours

_METHOD_MAP = {
    "status_code":  "status_code",
    "message":      "text_not_present",
    "response_url": "response_url",
}


def _load_cache() -> Optional[Dict]:
    try:
        if _CACHE_FILE.exists():
            age = time.time() - _CACHE_FILE.stat().st_mtime
            if age < _CACHE_TTL:
                return json.loads(_CACHE_FILE.read_text())
    except Exception:
        pass
    return None


def _save_cache(data: dict):
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(data))
    except Exception:
        pass


async def fetch_sherlock_platforms(timeout: int = 30) -> Dict[str, dict]:
    # ── Try cache first ───────────────────────────────────────────────────────
    cached = _load_cache()
    if cached:
        return cached

    # ── Fetch from GitHub (try each URL in order) ─────────────────────────────
    raw = None
    last_error = None
    async with aiohttp.ClientSession() as session:
        for url in SHERLOCK_URLS:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status != 200:
                        last_error = f"HTTP {resp.status} from {url}"
                        continue
                    raw = await resp.json(content_type=None)
                    break  # success
            except Exception as e:
                last_error = f"{e} (trying {url})"
                continue
    if raw is None:
        raise RuntimeError(f"Sherlock fetch failed — all URLs tried. Last error: {last_error}")

    platforms = {}
    for name, info in raw.items():
        if not isinstance(info, dict): continue  # skip $schema etc.
        url_tmpl   = info.get("url", "")
        error_type = info.get("errorType", "status_code")
        if not url_tmpl or "{}" not in url_tmpl:
            continue
        method = _METHOD_MAP.get(error_type)
        if not method:
            continue
        url  = url_tmpl.replace("{}", "{username}")
        pdef: dict = {
            "url": url, "method": method,
            "category": "sherlock", "color": "#a78bfa", "source": "sherlock",
        }
        if method == "status_code":
            pdef["found"] = [200]
        elif method == "text_not_present":
            em = info.get("errorMsg", "")
            pdef["not_found_text"] = em[0] if isinstance(em, list) else em
        elif method == "response_url":
            pdef["error_url"] = info.get("errorUrl", "")
        platforms[name] = pdef

    _save_cache(platforms)
    return platforms


async def load_with_fallback(timeout: int = 30) -> Dict[str, dict]:
    cached = _load_cache()
    if cached:
        age = int(time.time() - _CACHE_FILE.stat().st_mtime)
        print(f"  [cache] Sherlock data loaded from cache ({age}s old)")
        return cached
    try:
        p = await fetch_sherlock_platforms(timeout=timeout)
        _save_cache(p)
        print(f"  [cache] Sherlock data downloaded and cached ({len(p)} platforms)")
        return p
    except Exception as e:
        print(f"\n  [!] Sherlock adapter warning: {e}")
        print(f"  [!] Try --sherlock-timeout 60 or check your network connection\n")
        return {}
