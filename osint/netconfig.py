"""
Helix — Outbound network / proxy configuration.

Every HTTP probe Helix makes used to leave from the analyst's real IP. This
module centralises proxy selection so the checker, the email checker, the
intelligence modules and the third-party adapters all egress the same way.

Usage:
    netconfig.set_proxy("socks5://127.0.0.1:9050")
    connector = netconfig.build_connector(limit=20)
    async with netconfig.new_session(connector=connector) as s:
        await s.get(url, **netconfig.request_kwargs())
"""

import os
from typing import Optional
from urllib.parse import urlparse, urlunparse

import aiohttp

try:
    from aiohttp_socks import ProxyConnector
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

HTTP_SCHEMES  = ("http", "https")
SOCKS_SCHEMES = ("socks4", "socks4a", "socks5", "socks5h")
SUPPORTED_SCHEMES = HTTP_SCHEMES + SOCKS_SCHEMES

TOR_PROXY = "socks5://127.0.0.1:9050"

_PROXY: Optional[str] = None


def _scheme(url: str) -> str:
    return urlparse(url).scheme.lower()


def is_socks(url: Optional[str] = None) -> bool:
    target = _PROXY if url is None else url
    return bool(target) and _scheme(target) in SOCKS_SCHEMES


def redact(url: Optional[str]) -> str:
    """Strip proxy credentials so they never reach logs or reports."""
    if not url:
        return ""
    p = urlparse(url)
    if not p.password and not p.username:
        return url
    host = p.hostname or ""
    if p.port:
        host = f"{host}:{p.port}"
    return urlunparse((p.scheme, f"***@{host}", p.path, p.params, p.query, p.fragment))


def set_proxy(url: Optional[str]) -> Optional[str]:
    """
    Validate and install the global proxy. Pass None/"" to clear it.
    Raises ValueError on an unusable proxy URL — callers should surface the
    message and abort rather than silently scanning from the real IP.
    """
    global _PROXY

    if not url:
        _PROXY = None
        return None

    url = url.strip()
    p   = urlparse(url)

    if p.scheme.lower() not in SUPPORTED_SCHEMES:
        raise ValueError(
            f"unsupported proxy scheme '{p.scheme or url}' — "
            f"use one of: {', '.join(SUPPORTED_SCHEMES)}"
        )
    if not p.hostname:
        raise ValueError(f"proxy URL is missing a host: {url}")
    if p.scheme.lower() in SOCKS_SCHEMES and not HAS_SOCKS:
        raise ValueError(
            "SOCKS proxy support needs aiohttp-socks — pip install aiohttp-socks"
        )

    _PROXY = url

    # holehe (and any other library that builds its own session) never sees our
    # per-request proxy kwarg, so mirror HTTP proxies into the environment that
    # every trust_env=True session reads. SOCKS reaches those sessions through
    # build_connector() instead, since aiohttp cannot honour socks:// from env.
    if not is_socks(url):
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            os.environ[var] = url

    return _PROXY


def get_proxy() -> Optional[str]:
    return _PROXY


def request_kwargs() -> dict:
    """
    Per-request kwargs for session.get()/post(). SOCKS is applied at the
    connector level, so it contributes nothing here.
    """
    if _PROXY and not is_socks():
        return {"proxy": _PROXY}
    return {}


def curl_kwargs() -> dict:
    """Proxy kwargs for curl_cffi, which takes a requests-style proxies dict."""
    if not _PROXY:
        return {}
    return {"proxies": {"http": _PROXY, "https": _PROXY}}


def build_connector(**kwargs) -> aiohttp.BaseConnector:
    """TCPConnector, or a SOCKS-aware connector when a socks:// proxy is set."""
    if _PROXY and is_socks():
        return ProxyConnector.from_url(_PROXY, **kwargs)
    return aiohttp.TCPConnector(**kwargs)


def new_session(connector: aiohttp.BaseConnector = None, **kwargs) -> aiohttp.ClientSession:
    """ClientSession that honours the configured proxy and HTTP(S)_PROXY env vars."""
    kwargs.setdefault("trust_env", True)
    if connector is None:
        connector = build_connector()
    return aiohttp.ClientSession(connector=connector, **kwargs)


def describe() -> str:
    """One-line egress description for the CLI header."""
    if _PROXY:
        return f"proxy {redact(_PROXY)}"
    for var in ("ALL_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if os.environ.get(var):
            return f"env {var}={redact(os.environ[var])}"
    return "DIRECT — probes leave from your real IP"
