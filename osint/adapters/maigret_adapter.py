"""
Helix — Maigret Adapter
Fetches soxoj/maigret site database at runtime.
Maigret has more sophisticated detection than Sherlock — uses presenceStrs,
absenceStrs, and more platform-specific logic. Cached 24h locally.
github.com/soxoj/maigret
"""
import aiohttp, json, time
from pathlib import Path
from typing import Dict, Optional
from osint import netconfig

MAIGRET_URL = (
    "https://raw.githubusercontent.com/soxoj/maigret/"
    "main/maigret/resources/data.json"
)
_CACHE_DIR  = Path.home() / ".cache" / "helix"
_CACHE_FILE = _CACHE_DIR / "maigret_data.json"
_CACHE_TTL  = 86_400   # 24 hours


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


def _translate(name: str, info: dict) -> Optional[dict]:
    """Translate a Maigret site entry to Helix platform schema."""
    url_tmpl = info.get("url","")
    if not url_tmpl or "{username}" not in url_tmpl:
        # Try to construct from urlMain + username
        url_main = info.get("urlMain","")
        if not url_main:
            return None
        url_tmpl = url_main.rstrip("/") + "/{username}"

    # Detection method
    presence  = info.get("presenceStrs",[])
    absence   = info.get("absenceStrs",[])
    status_ok = info.get("isNSFW", False) is not None  # field presence check

    if absence and isinstance(absence, list) and absence[0]:
        pdef = {
            "url":            url_tmpl,
            "method":         "text_not_present",
            "not_found_text": absence[0],
            "category":       _categorize(info),
            "color":          "#38bdf8",
            "source":         "maigret",
        }
    elif presence and isinstance(presence, list) and presence[0]:
        pdef = {
            "url":        url_tmpl,
            "method":     "text_present",
            "found_text": presence[0],
            "category":   _categorize(info),
            "color":      "#38bdf8",
            "source":     "maigret",
        }
    else:
        pdef = {
            "url":      url_tmpl,
            "method":   "status_code",
            "found":    [200],
            "category": _categorize(info),
            "color":    "#38bdf8",
            "source":   "maigret",
        }

    return pdef


def _categorize(info: dict) -> str:
    cats = info.get("tags",[]) or []
    if isinstance(cats, str):
        cats = [cats]
    tag_map = {
        "social": "social", "coding": "dev", "gaming": "gaming",
        "music": "content", "video": "content", "art": "content",
        "photo": "content", "forum": "forum", "blog": "content",
        "nsfw": "other", "finance": "other",
    }
    for tag in cats:
        if isinstance(tag, str):
            mapped = tag_map.get(tag.lower())
            if mapped:
                return mapped
    return "other"


async def fetch_maigret_platforms(timeout: int = 30) -> Dict[str, dict]:
    cached = _load_cache()
    if cached:
        return cached

    async with netconfig.new_session() as session:
        try:
            async with session.get(
                MAIGRET_URL,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                raw = await resp.json(content_type=None)
        except Exception as e:
            raise RuntimeError(f"Maigret fetch failed: {e}")

    platforms = {}

    # Maigret format: flat dict {SiteName: {url, presenceStrs, absenceStrs, ...}}
    # or nested under a "sites" key in some versions
    if isinstance(raw, dict):
        sites = raw.get("sites", raw)
    else:
        raise RuntimeError("Unexpected Maigret data format")

    for name, info in sites.items():
        if not isinstance(info, dict):
            continue
        if info.get("disabled") or info.get("valid") is False:
            continue
        pdef = _translate(name, info)
        if pdef:
            platforms[name] = pdef

    if platforms:
        _save_cache(platforms)
    return platforms


async def load_with_fallback(timeout: int = 30, include_nsfw: bool = False) -> Dict[str, dict]:
    cached = _load_cache()
    if cached:
        age = int(time.time() - _CACHE_FILE.stat().st_mtime)
        print(f"  [cache] Maigret data loaded ({age}s old, {len(cached)} platforms)")
        return cached
    try:
        p = await fetch_maigret_platforms(timeout=timeout)
        print(f"  [cache] Maigret data downloaded: {len(p)} platforms cached")
        return p
    except Exception as e:
        print(f"\n  [!] Maigret adapter warning: {e}")
        print(f"  [!] Try: --maigret-timeout 60\n")
        return {}
