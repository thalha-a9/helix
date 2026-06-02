"""
OSINT Grapher v2.0 — Holehe Adapter
Wraps holehe (pip install holehe) to probe email registration
across 120+ platforms via password-reset API fingerprinting.
Falls back gracefully if holehe is not installed.
"""

from typing import List

HOLEHE_AVAILABLE = False
try:
    import holehe  # noqa
    HOLEHE_AVAILABLE = True
except ImportError:
    pass

# Category hints for known holehe modules
_CATEGORY_HINTS = {
    "twitter": "social",  "instagram": "social",  "facebook": "social",
    "snapchat": "social", "tumblr": "social",      "pinterest": "social",
    "github":   "dev",    "gitlab":   "dev",        "replit": "dev",
    "adobe":    "other",  "amazon":   "other",      "apple": "other",
    "netflix":  "content","spotify":  "content",    "twitch": "content",
    "steam":    "gaming", "google":   "other",      "paypal": "other",
}

def _category(name: str) -> str:
    return _CATEGORY_HINTS.get(name.lower(), "other")

def _color(category: str) -> str:
    colors = {
        "social": "#e879f9", "dev": "#34d399", "content": "#fb923c",
        "gaming": "#60a5fa", "other": "#94a3b8",
    }
    return colors.get(category, "#94a3b8")


async def run_holehe(email: str, progress_cb=None) -> List[dict]:
    """
    Run holehe against an email address and return results
    in OSINT Grapher's universal schema.
    Raises RuntimeError if holehe is not installed.
    """
    if not HOLEHE_AVAILABLE:
        raise RuntimeError(
            "holehe is not installed. Run: pip install holehe"
        )

    # holehe exposes an async generator via holehe.core
    from holehe.core import get_functions
    import asyncio, aiohttp

    modules  = get_functions()
    results  = []
    done     = 0
    total    = len(modules)

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as client:
        for module in modules:
            out = []
            try:
                await module(email, client, out)
            except Exception:
                pass  # individual module failure must not crash scan

            for entry in out:
                name  = entry.get("name", module.__name__)
                found = entry.get("exists", False)
                cat   = _category(name)
                results.append({
                    "platform":    name,
                    "url":         entry.get("domain", f"https://{name}.com"),
                    "category":    cat,
                    "color":       _color(cat),
                    "found":       found,
                    "error":       entry.get("error"),
                    "confidence":  "high",   # holehe uses API-level probes
                    "bio_links":   {},
                    "target_type": "email",
                    "source":      "holehe",
                    "status_code": None,
                })

            done += 1
            if progress_cb:
                progress_cb(done, total)

    return results


async def load_with_fallback(email: str, progress_cb=None) -> List[dict]:
    """Run holehe with a clean warning on failure."""
    if not HOLEHE_AVAILABLE:
        print("\n  [!] holehe not installed — skipping email deep scan.")
        print("  [!] Install with: pip install holehe\n")
        return []
    try:
        return await run_holehe(email, progress_cb)
    except Exception as e:
        print(f"\n  [!] holehe error: {e}\n")
        return []
