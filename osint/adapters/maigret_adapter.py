"""
Helix: Maigret Adapter
Fetches soxoj/maigret site database at runtime.
Each entry is translated to a Helix rule: its own address and "not found"
texts, or those of its engine (XenForo, Discourse, uCoz, MediaWiki ...).
Cached 24h locally.
github.com/soxoj/maigret
"""
import aiohttp, json, re, time
from pathlib import Path
from typing import Dict, Optional
from osint import netconfig

MAIGRET_URL = (
    "https://raw.githubusercontent.com/soxoj/maigret/"
    "main/maigret/resources/data.json"
)
_CACHE_DIR  = Path.home() / ".cache" / "helix"
# v2: entries carry an "nsfw" flag. Version-1 caches lacked it, so --nsfw had
# no effect on Maigret at all; a new file name makes them refetch.
# v3: entries carry every absence string, not just the first.
# v4: entries carry the account Maigret lists as existing ("known").
# v5: engine entries (XenForo, Discourse, uCoz ...) get their engine's address.
_CACHE_FILE = _CACHE_DIR / "maigret_data_v5.json"

# Tags Maigret uses for adult sites. "dating" is its own category in both
# Maigret and WhatsMyName and is kept.
NSFW_TAGS = {"porn", "erotic", "webcam", "nsfw", "adult"}


def is_nsfw(info: dict) -> bool:
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return bool(info.get("isNSFW")) or any(str(t).lower() in NSFW_TAGS for t in tags)


def without_nsfw(platforms: Dict[str, dict], include_nsfw: bool) -> Dict[str, dict]:
    return platforms if include_nsfw else {k: v for k, v in platforms.items() if not v.get("nsfw")}
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


def _with_engine(info: dict, engines: Optional[dict]) -> Optional[dict]:
    """
    The entry with its engine's fields filled in, or None when it names an
    engine the database does not define.

    Two thirds of Maigret's entries (5,870 of 8,969 on 10 Nov 2026) give no
    address of their own, only `"engine": "XenForo"` (or Discourse, uCoz,
    MediaWiki, Gitea and so on). The engine holds the address pattern and
    the "not found" texts for every forum of that kind; the entry's own
    fields win over it.
    """
    engine = info.get("engine")
    if not engine:
        return info
    base = ((engines or {}).get(engine) or {}).get("site")
    if not isinstance(base, dict):
        return None
    return {**base, **info}


def _address(template, info: dict) -> Optional[str]:
    """A Maigret address pattern with the site's own parts filled in, or None
    when it cannot be requested as a username lookup."""
    if not isinstance(template, str) or "{username}" not in template:
        return None
    url = (template.replace("{urlMain}", info.get("urlMain") or "{urlMain}")
                   .replace("{urlSubpath}", info.get("urlSubpath") or ""))
    # "https://site.example/" + "/members/" must not become "//members/".
    url = re.sub(r"(?<!:)/{2,}", "/", url)
    # Anything still templated besides {username} cannot be requested.
    if re.search(r"\{(?!username\})[^}]*\}", url) or not url.startswith("http"):
        return None
    return url


def _strings(value) -> list:
    value = [value] if isinstance(value, str) else (value or [])
    return [x for x in value if isinstance(x, str) and x]


# Maigret's two fediverse engines are the same lookups Helix has its own
# rules for, with WebFinger as the second rule.
_FEDIVERSE_ENGINES = {"Mastodon": "mastodon", "Lemmy": "lemmy"}


def _translate(name: str, info: dict, engines: Optional[dict] = None) -> Optional[dict]:
    """Translate a Maigret site entry to Helix platform schema."""
    # Some entries take an account id (vk_id, steam_id...), not a username.
    if info.get("type", "username") != "username":
        return None
    own = info
    info = _with_engine(info, engines)
    if info is None:
        return None
    # A lookup that has to be POSTed cannot be made by a plain GET.
    if str(info.get("requestMethod") or "GET").upper() not in ("GET", "HEAD"):
        return None
    # No address pattern, no check. Helix used to guess "site/{username}"
    # here, which answered 404 for every name on thousands of forums.
    url_tmpl = _address(info.get("url"), info)
    if not url_tmpl:
        return None
    probe = _address(info.get("urlProbe"), info)
    labels = {"category": _categorize(info), "color": "#38bdf8", "source": "maigret"}

    fedi = _FEDIVERSE_ENGINES.get(own.get("engine"))
    if fedi and not own.get("url") and not own.get("urlProbe"):
        from osint.adapters.fediverse_adapter import host_of, platform_for
        pdef = {**platform_for(host_of(url_tmpl), fedi), **labels}
        return _finish(pdef, info)

    # Detection method. A page showing any of the absence strings is not a
    # profile. Olx.pl lists two; reading only the first let its generic page
    # (which has the second) through as an account.
    #
    # Where an entry lists absence strings, Maigret's presence strings
    # ("presenseStrs") are not used on top: they miss real accounts (Twitter,
    # Roblox, Chess.com, Gravatar). They are the rule only where the entry
    # has nothing else to go by, and then the page must name the user too.
    check_type = info.get("checkType") or "status_code"
    absence = _strings(info.get("absenceStrs"))
    presence = _strings(info.get("presenseStrs") or info.get("presenceStrs"))

    if absence:
        pdef = {"url": url_tmpl, "method": "text_not_present",
                "not_found_text": absence[0], "not_found_texts": absence, **labels}
    elif check_type == "message" and presence:
        pdef = {"url": url_tmpl, "method": "text_present", "found_text": presence[0],
                "found_texts": presence, "name_in_page": True, **labels}
    elif check_type == "response_url" and isinstance(info.get("errorUrl"), str) \
            and info["errorUrl"].startswith("http") and "{" not in info["errorUrl"]:
        pdef = {"url": url_tmpl, "method": "response_url", "error_url": info["errorUrl"], **labels}
    else:
        pdef = {"url": url_tmpl, "method": "status_code", "found": [200], **labels}

    if probe and probe != url_tmpl:
        pdef["check_url"] = probe
    return _finish(pdef, info)


def _finish(pdef: dict, info: dict) -> dict:
    """The parts every translated entry gets, whatever its rule."""
    # Request headers the site's lookup needs (an app id, an API accept type).
    headers = info.get("headers")
    if isinstance(headers, dict) and headers and all(
            isinstance(k, str) and isinstance(v, str) and not re.search(r"[\r\n]", k + v)
            for k, v in headers.items()):
        pdef["headers"] = dict(headers)
    # Sites Maigret marks as reading the TLS fingerprint get a browser's,
    # when curl_cffi is installed.
    protection = info.get("protection") or []
    if isinstance(protection, list) and "tls_fingerprint" in protection:
        pdef["tls_impersonate"] = True
    # The account Maigret lists as existing on this site: the daily site
    # check looks for it to prove the rule still finds a real account.
    claimed = info.get("usernameClaimed")
    if isinstance(claimed, str) and re.fullmatch(r"[A-Za-z0-9._\-]{1,50}", claimed):
        pdef["known"] = claimed
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
            raise RuntimeError(f"Maigret fetch failed: {e}") from e

    platforms = {}

    # Maigret format: flat dict {SiteName: {url, presenceStrs, absenceStrs, ...}}
    # or nested under a "sites" key in some versions
    if isinstance(raw, dict):
        sites = raw.get("sites", raw)
    else:
        raise RuntimeError("Unexpected Maigret data format")

    engines = raw.get("engines") if isinstance(raw.get("engines"), dict) else {}
    for name, info in sites.items():
        if not isinstance(info, dict):
            continue
        if info.get("disabled") or info.get("valid") is False:
            continue
        pdef = _translate(name, info, engines)
        if pdef:
            if is_nsfw(info):
                pdef["nsfw"] = True
            platforms[name] = pdef

    if platforms:
        _save_cache(platforms)
    return platforms


async def load_with_fallback(timeout: int = 30, include_nsfw: bool = False) -> Dict[str, dict]:
    cached = _load_cache()
    if cached:
        age = int(time.time() - _CACHE_FILE.stat().st_mtime)
        print(f"  [cache] Maigret data loaded ({age}s old, {len(cached)} platforms)")
        return without_nsfw(cached, include_nsfw)
    try:
        p = await fetch_maigret_platforms(timeout=timeout)
        print(f"  [cache] Maigret data downloaded: {len(p)} platforms cached")
        return without_nsfw(p, include_nsfw)
    except Exception as e:
        print(f"\n  [!] Maigret adapter warning: {e}")
        print("  [!] Try: --maigret-timeout 60\n")
        return {}
