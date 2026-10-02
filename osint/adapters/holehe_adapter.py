"""
Helix — Holehe Adapter
Wraps holehe (pip install holehe) to check which of ~120 sites an email
address is registered on, via their sign-up / login / recovery endpoints.

Holehe's modules are written for an httpx client. Earlier versions of this
adapter passed an aiohttp session and called get_functions() without its
required argument, so every run failed and reported nothing.

OPSEC:
  - Modules that trigger a password-recovery email (Adobe, Mail.ru, OK.ru,
    Samsung) are skipped by default: they can alert the target.
  - Traffic follows --proxy / --tor. SOCKS needs httpx's SOCKS extra
    (pip install "httpx[socks]"); without it the scan refuses to run rather
    than leaving from the real IP.

A module that was rate-limited or failed is reported as not checked
("error"), never as "not registered".
"""

import asyncio
from types import SimpleNamespace
from typing import List

from osint import netconfig

HOLEHE_AVAILABLE = False
try:
    import holehe  # noqa: F401
    HOLEHE_AVAILABLE = True
except ImportError:
    pass

CONCURRENCY = 12
TIMEOUT = 15

_CATEGORY_HINTS = {
    "twitter": "social",  "instagram": "social",  "facebook": "social",
    "snapchat": "social", "tumblr": "social",      "pinterest": "social",
    "github":   "dev",    "gitlab":   "dev",        "replit": "dev",
    "docker":   "dev",    "codepen":  "dev",        "devrant": "dev",
    "adobe":    "other",  "amazon":   "other",      "apple": "other",
    "netflix":  "content", "spotify": "content",    "twitch": "content",
    "soundcloud": "content", "wattpad": "content",
    "steam":    "gaming", "google":   "other",      "paypal": "other",
}
_COLORS = {"social": "#e879f9", "dev": "#34d399", "content": "#fb923c",
           "gaming": "#60a5fa", "other": "#94a3b8"}


def _category(name: str) -> str:
    return _CATEGORY_HINTS.get(name.lower(), "other")


def _proxy_url():
    """httpx proxy for the configured egress, or raise if it cannot be honoured."""
    proxy = netconfig.get_proxy()
    if not proxy:
        return None
    if netconfig.is_socks(proxy):
        try:
            import socksio  # noqa: F401
        except ImportError:
            raise RuntimeError('SOCKS proxy needs httpx\'s SOCKS support: pip install "httpx[socks]"')
        scheme = proxy.split("://", 1)[0].lower()
        if scheme == "socks5h":            # httpx resolves through the proxy for socks5
            proxy = "socks5" + proxy[len(scheme):]
    return proxy


def _holehe_modules() -> dict:
    """
    holehe's site modules by full name. holehe.core.import_submodules walks
    packages by short name, so its "holehe.modules.osint" sub-package
    resolves to Helix's own "osint" package and the import fails. Walking
    with the full prefix avoids the collision.
    """
    import importlib
    import pkgutil
    import holehe.modules as hm
    return {name: importlib.import_module(name)
            for _, name, _ in pkgutil.walk_packages(hm.__path__, prefix="holehe.modules.")}


def to_result(entry: dict) -> dict:
    """One holehe output entry -> Helix result."""
    name = entry.get("name", "?")
    cat = _category(name)
    domain = entry.get("domain") or f"{name}.com"
    failed = bool(entry.get("rateLimit")) or entry.get("exists") is None
    return {
        "platform":    name,
        "url":         domain if domain.startswith("http") else f"https://{domain}",
        "category":    cat,
        "color":       _COLORS.get(cat, "#94a3b8"),
        "found":       bool(entry.get("exists")) and not failed,
        "error":       "not checked — rate-limited or blocked" if failed else None,
        "confidence":  "high",
        "bio_links":   {},
        "target_type": "email",
        "source":      "holehe",
        "status_code": None,
        "recovery_hint": entry.get("emailrecovery") or entry.get("phoneNumber") or "",
    }


async def run_holehe(email: str, progress_cb=None, password_recovery: bool = False) -> List[dict]:
    if not HOLEHE_AVAILABLE:
        raise RuntimeError("holehe is not installed. Run: pip install holehe")
    import logging
    import httpx
    from holehe.core import get_functions, launch_module
    logging.getLogger("bs4.dammit").setLevel(logging.ERROR)   # decode warnings from holehe modules

    modules = get_functions(_holehe_modules(),
                            SimpleNamespace(nopasswordrecovery=not password_recovery))
    total, done = len(modules), 0
    sem = asyncio.Semaphore(CONCURRENCY)
    outputs: List[dict] = []

    async with httpx.AsyncClient(timeout=TIMEOUT, proxy=_proxy_url(), trust_env=True) as client:
        async def one(module):
            nonlocal done
            out: List[dict] = []
            async with sem:
                await launch_module(module, email, client, out)   # holehe's own error wrapper
            outputs.extend(out)
            done += 1
            if progress_cb:
                progress_cb(done, total)

        await asyncio.gather(*(one(m) for m in modules))

    return [to_result(e) for e in outputs]


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
