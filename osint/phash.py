"""
Helix: Perceptual Avatar Hash Matching
Fix: default avatar filtering: if 3+ platforms share the same hash,
it's a CDN default/placeholder (Mastodon grey silhouette, etc.) and
must NOT be reported as a match.
"""
import asyncio
import aiohttp
import io
from typing import Optional
from osint import netconfig

try:
    import imagehash
    from PIL import Image
    HAS_PHASH = True
except ImportError:
    HAS_PHASH = False

import re

TIMEOUT = aiohttp.ClientTimeout(total=10)

# Avatars come from strangers' accounts, so decoding one is decoding
# attacker-controlled input. Only the formats profile pictures actually use
# are opened (most image-library vulnerabilities sit in rarer decoders), and
# anything larger than a sane avatar is refused before it is decoded.
AVATAR_FORMATS = ["JPEG", "PNG", "GIF", "WEBP"]
MAX_AVATAR_PIXELS = 16_000_000       # 4000 x 4000
MAX_AVATAR_BYTES = 5 * 1024 * 1024
SAFE_PILLOW = (13, 0)                # 20 decoder vulnerabilities fixed in 13.0 (2026)


def pillow_warning() -> str:
    """A warning when the installed Pillow has known decoder vulnerabilities, else ''."""
    if not HAS_PHASH:
        return ""
    import PIL
    try:
        ver = tuple(int(x) for x in PIL.__version__.split(".")[:2])
    except ValueError:
        return ""
    if ver >= SAFE_PILLOW:
        return ""
    return (f"Pillow {PIL.__version__} has known image-decoder vulnerabilities and --phash opens "
            f"pictures from strangers' accounts. Upgrade: pip install -U 'Pillow>=13' "
            f"(needs Python 3.11+). Helix opens only JPEG/PNG/GIF/WebP meanwhile.")


def open_avatar(data: bytes):
    """Decode an avatar defensively; None for anything that is not a plain picture."""
    if not data or len(data) > MAX_AVATAR_BYTES:
        return None
    try:
        img = Image.open(io.BytesIO(data), formats=AVATAR_FORMATS)
        w, h = img.size
        if w * h > MAX_AVATAR_PIXELS or w < 8 or h < 8:
            return None
        img.seek(0)                  # first frame only for animated GIF/WebP
        return img.convert("RGB")
    except Exception:
        return None

# Bits (of 64) two perceptual hashes may differ by and still be the same
# picture. 10 let simple, unrelated images (initials on a flat colour) match.
MATCH_THRESHOLD = 6

# og:image URLs that are a platform default or a site-wide card, not the
# user's picture. Two sites' defaults must never read as "same person".
_DEFAULT_IMAGE = re.compile(
    r"missing\.png|default_profile|og-default|default[-_]?avatar|avatar[-_]?default|"
    r"no[-_]?avatar|placeholder|anonymous|/defaults?/|/og/image/|web-capture|"
    r"/background/|/opengraph/|card\.jpg|uploads/articles/|og[-_]image|social[-_]?(?:card|preview)",
    re.I)


def is_default_image(url: str) -> bool:
    return bool(_DEFAULT_IMAGE.search(url or ""))


def _too_plain(img) -> bool:
    """Blank or flat images (letters on a colour, solid fills) carry no identity."""
    from PIL import ImageStat
    return max(ImageStat.Stat(img.convert("L")).stddev) < 20

MAX_REDIRECTS = 3


async def _fetch_image(session, url: str) -> Optional[bytes]:
    """
    The avatar URL comes from a stranger's page, so every hop is checked to be
    a public address before it is requested, and redirects are followed by
    hand for the same reason (a public URL may redirect to 127.0.0.1).
    """
    from urllib.parse import urljoin
    try:
        for _ in range(MAX_REDIRECTS + 1):
            if await netconfig.public_url(url):
                return None
            async with session.get(url, timeout=TIMEOUT, allow_redirects=False,
                                   **netconfig.request_kwargs()) as r:
                if r.status in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                    url = urljoin(url, r.headers["Location"])
                    continue
                if r.status == 200:
                    return await netconfig.read_body(r, MAX_AVATAR_BYTES)
                return None
    except Exception:
        pass
    return None

async def hash_all_avatars(found: list) -> dict:
    """Download and pHash all avatar URLs. Returns {platform: hash_str}."""
    if not HAS_PHASH:
        return {}

    urls = {
        r["platform"]: r.get("avatar_url", "")
        for r in found
        if r.get("avatar_url", "").startswith("http") and not is_default_image(r["avatar_url"])
    }
    if not urls:
        return {}

    hashes = {}
    connector = netconfig.public_only_connector(limit=20, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        tasks = {plat: _fetch_image(session, url) for plat, url in urls.items()}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for plat, data in zip(tasks.keys(), results):
            if isinstance(data, bytes) and data:
                img = open_avatar(data)
                if img is None:
                    continue
                try:
                    if _too_plain(img):
                        continue
                    phash = str(imagehash.phash(img))
                    hashes[plat] = phash
                except Exception:
                    pass
    return hashes


def find_matches(hashes: dict, threshold: int = MATCH_THRESHOLD) -> list:
    """
    Find similar avatar hashes.
    CRITICAL FIX: any hash shared by 3+ platforms is a default/placeholder
    avatar (Mastodon grey silhouette, CDN placeholder, etc.): skip entirely.
    Real profile pictures appear on 1-2 platforms at most.
    """
    if not HAS_PHASH or not hashes:
        return []

    platforms = list(hashes.keys())
    hash_objs = {}
    for p, h in hashes.items():
        try:
            hash_objs[p] = imagehash.hex_to_hash(h)
        except Exception:
            pass

    # Count how many platforms share each hash value (exact match)
    from collections import Counter
    hash_counts = Counter(hashes.values())

    # Any hash appearing 3+ times is a default avatar, exclude all platforms with it
    default_hashes = {h for h, count in hash_counts.items() if count >= 3}

    matches = []
    seen = set()

    for i, pa in enumerate(platforms):
        if pa not in hash_objs:
            continue
        # Skip if this platform has a default avatar hash
        if hashes[pa] in default_hashes:
            continue
        for pb in platforms[i+1:]:
            if pb not in hash_objs:
                continue
            if hashes[pb] in default_hashes:
                continue
            pair = tuple(sorted([pa, pb]))
            if pair in seen:
                continue
            seen.add(pair)
            try:
                dist = hash_objs[pa] - hash_objs[pb]
                if dist <= threshold:
                    conf = "99%" if dist == 0 else f"{max(0,100-dist*10)}%"
                    matches.append({
                        "platform_a":  pa,
                        "platform_b":  pb,
                        "distance":    int(dist),
                        "confidence":  conf,
                        "match_type":  "exact" if dist == 0 else "similar",
                    })
            except Exception:
                pass

    return sorted(matches, key=lambda x: x["distance"])
