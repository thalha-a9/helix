"""
Helix — Perceptual Hash Avatar Matcher  v3.2
Re-fetches profile pages when og:image not stored, so pHash works on
platforms that don't expose avatars via og:image (uses _AVATAR_PATTERNS).
Requires: pip install imagehash Pillow
"""
import asyncio, aiohttp, io, re
from typing import Dict, List, Optional

try:
    from PIL import Image
    import imagehash
    HAS_PHASH = True
except ImportError:
    HAS_PHASH = False

PHASH_MATCH   = 8
PHASH_NEAR    = 15

_AVATAR_PATTERNS = [
    r'<meta[^>]+property=["\']og:image["\']\s+content=["\']([^"\']+)["\']',
    r'<meta[^>]+content=["\']([^"\']+)["\']\s+property=["\']og:image["\']',
    r'"avatar_url"\s*:\s*"([^"]+)"',
    r'"profile_image_url"\s*:\s*"([^"]+)"',
    r'"profile_image_url_https"\s*:\s*"([^"]+)"',
    r'src=["\']([^"\']*(?:avatar|profile|photo)[^"\']*\.(jpg|jpeg|png|webp))["\']',
]

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Helix-OSINT/3.0)"}


def _extract_avatar_url(html: str) -> Optional[str]:
    for pat in _AVATAR_PATTERNS:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            url = m.group(1)
            if url.startswith("http"):
                return url
    return None


async def _fetch_page_avatar(session: aiohttp.ClientSession, profile_url: str) -> Optional[str]:
    """Re-fetch profile page and extract avatar URL from HTML."""
    if not profile_url:
        return None
    try:
        async with session.get(
            profile_url, headers=_HEADERS,
            timeout=aiohttp.ClientTimeout(total=12), ssl=False,
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                return None
            html = await resp.text(errors="ignore")
            return _extract_avatar_url(html)
    except Exception:
        return None


async def _hash_image(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    if not HAS_PHASH or not url:
        return None
    try:
        async with session.get(
            url, headers=_HEADERS,
            timeout=aiohttp.ClientTimeout(total=10), ssl=False,
        ) as resp:
            if resp.status != 200: return None
            ct = resp.headers.get("Content-Type","")
            if "image" not in ct and "octet" not in ct: return None
            data = await resp.read()
        img   = Image.open(io.BytesIO(data)).convert("RGB")
        return str(imagehash.phash(img))
    except Exception:
        return None


def _hamming(h1: str, h2: str) -> int:
    try:
        return imagehash.hex_to_hash(h1) - imagehash.hex_to_hash(h2)
    except Exception:
        return 999


async def hash_all_avatars(results: List[dict]) -> Dict[str, str]:
    """
    Hash avatars for all found results.
    Uses stored og:image first; re-fetches profile page if not available.
    """
    if not HAS_PHASH:
        return {}

    hashes    = {}
    sem       = asyncio.Semaphore(5)
    connector = aiohttp.TCPConnector(limit=8, force_close=True)

    async with aiohttp.ClientSession(connector=connector) as session:

        async def process(r):
            async with sem:
                avatar_url = r.get("avatar_url","")

                # If not stored, re-fetch profile page to extract it
                if not avatar_url:
                    avatar_url = await _fetch_page_avatar(session, r.get("url",""))
                    if avatar_url:
                        r["avatar_url"] = avatar_url   # cache for report

                if avatar_url:
                    h = await _hash_image(session, avatar_url)
                    if h:
                        hashes[r["platform"]] = h

        await asyncio.gather(*[process(r) for r in results if r.get("found")])

    return hashes


def find_matches(hashes: Dict[str, str]) -> List[dict]:
    platforms = list(hashes.keys())
    matches   = []
    for i in range(len(platforms)):
        for j in range(i+1, len(platforms)):
            p1, p2 = platforms[i], platforms[j]
            dist   = _hamming(hashes[p1], hashes[p2])
            if dist <= PHASH_MATCH:
                matches.append({
                    "platform_a": p1, "platform_b": p2,
                    "distance":   dist,
                    "confidence": "99%" if dist==0 else f"{max(70,99-dist*5)}%",
                    "match_type": "exact" if dist==0 else "near",
                })
            elif dist <= PHASH_NEAR:
                matches.append({
                    "platform_a": p1, "platform_b": p2,
                    "distance":   dist,
                    "confidence": f"{max(50,80-dist*3)}%",
                    "match_type": "possible",
                })
    return sorted(matches, key=lambda x: x["distance"])
