"""
Helix: Outbound network / proxy configuration.

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
from aiohttp.abc import AbstractResolver

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
    Raises ValueError on an unusable proxy URL, callers should surface the
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
            f"unsupported proxy scheme '{p.scheme or url}': "
            f"use one of: {', '.join(SUPPORTED_SCHEMES)}"
        )
    if not p.hostname:
        raise ValueError(f"proxy URL is missing a host: {url}")
    if p.scheme.lower() in SOCKS_SCHEMES and not HAS_SOCKS:
        raise ValueError(
            "SOCKS proxy support needs aiohttp-socks: pip install aiohttp-socks"
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
    proxy = _PROXY
    # curl resolves names locally for socks5:// and socks4://: every probed
    # platform would leak to the local DNS resolver (and Tor's .onion names
    # would not resolve at all). The "h" variants resolve at the proxy.
    scheme = _scheme(proxy)
    if scheme in ("socks5", "socks4"):
        proxy = ("socks5h" if scheme == "socks5" else "socks4a") + proxy[len(scheme):]
    return {"proxies": {"http": proxy, "https": proxy}}


_INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet",
                      ".corp", ".onion")


def egress_is_direct() -> bool:
    """True when requests leave this machine directly (no explicit or env proxy)."""
    if _PROXY:
        return False
    return not any(os.environ.get(v) for v in
                   ("ALL_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"))


def _ip_is_public(addr: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def _resolve(host: str, port: int) -> list:
    import asyncio
    import socket
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [i[4][0] for i in infos]


async def public_url(url: str) -> Optional[str]:
    """
    None when `url` is safe to fetch on behalf of a page Helix scanned, else why
    not. URLs taken from strangers' pages (avatars) must not make the analyst's
    machine request localhost, the LAN or cloud metadata addresses (SSRF).
    """
    p = urlparse(url or "")
    if p.scheme.lower() not in ("http", "https"):
        return f"scheme {p.scheme or '(none)'} not allowed"
    host = (p.hostname or "").rstrip(".").lower()
    if not host:
        return "no host"
    if host == "localhost" or host.endswith(_INTERNAL_SUFFIXES) or "." not in host and ":" not in host:
        return f"internal host {host}"
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return None if _ip_is_public(host) else f"non-public address {host}"
    except ValueError:
        pass
    if _PROXY:
        # An explicitly chosen --proxy/--tor resolves names itself; resolving
        # here would leak every avatar host to the local DNS. (A proxy only
        # inherited from the environment is still checked below.)
        return None
    try:
        addrs = await _resolve(host, p.port or 443)
    except OSError:
        return f"cannot resolve {host}"
    bad = sorted({a for a in addrs if not _ip_is_public(a)})
    return f"{host} resolves to non-public {', '.join(bad)}" if bad else None


class PublicOnlyResolver(AbstractResolver):
    """
    Resolver that drops non-public addresses, so the connection is made to an
    address that was checked: a hostile DNS server answering "public" to
    public_url() and "127.0.0.1" a moment later (rebinding) gets nothing.
    """

    def __init__(self):
        self._inner = None

    async def resolve(self, host: str, port: int = 0, family=0):
        import socket
        if self._inner is None:
            self._inner = aiohttp.ThreadedResolver()
        infos = await self._inner.resolve(host, port, family or socket.AF_INET)
        public = [i for i in infos if _ip_is_public(i["host"])]
        if not public:
            raise OSError(f"{host} resolves only to non-public addresses")
        return public

    async def close(self):
        if self._inner is not None:
            await self._inner.close()


def public_only_connector(**kwargs) -> aiohttp.BaseConnector:
    """Connector for fetching URLs taken from scanned pages (avatars)."""
    if _PROXY or not egress_is_direct():
        return build_connector(**kwargs)     # the proxy connects, not us
    kwargs.setdefault("ttl_dns_cache", 0)
    return aiohttp.TCPConnector(resolver=PublicOnlyResolver(), **kwargs)


async def proxy_reachable(timeout: float = 5.0) -> Optional[str]:
    """
    None when the configured proxy accepts a TCP connection, else why not.
    Without this, a dead proxy (Tor not started) fails every probe and the scan
    reads as "0 accounts found": the most misleading result possible.
    """
    import asyncio
    if not _PROXY:
        return None
    p = urlparse(_PROXY)
    port = p.port or {"http": 80, "https": 443}.get(p.scheme.lower(), 1080)
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(p.hostname, port), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return None
    except asyncio.TimeoutError:
        return f"no answer from {p.hostname}:{port} within {timeout:.0f}s"
    except OSError as e:
        return f"cannot connect to {p.hostname}:{port} ({e.strerror or type(e).__name__})"


def build_connector(**kwargs) -> aiohttp.BaseConnector:
    """TCPConnector, or a SOCKS-aware connector when a socks:// proxy is set."""
    if _PROXY and is_socks():
        # rdns: hostnames are resolved by the proxy, never locally (no DNS leak).
        kwargs.setdefault("rdns", True)
        return ProxyConnector.from_url(_PROXY, **kwargs)
    # aiohttp silently switches to aiodns when it is installed (maigret pulls it
    # in), and c-ares times out under thousands of concurrent lookups. The
    # system resolver plus a DNS cache holds up at full-database scale.
    kwargs.setdefault("resolver", aiohttp.ThreadedResolver())
    kwargs.setdefault("ttl_dns_cache", 300)
    return aiohttp.TCPConnector(**kwargs)


# aiohttp rejects response header lines over 8,190 bytes, so sites with large
# cookies or CSP headers would fail outright.
MAX_HEADER_BYTES = 65536


def _header_limits() -> dict:
    import inspect
    params = inspect.signature(aiohttp.ClientSession.__init__).parameters
    return {k: MAX_HEADER_BYTES for k in ("max_line_size", "max_field_size") if k in params}


def new_session(connector: aiohttp.BaseConnector = None, **kwargs) -> aiohttp.ClientSession:
    """ClientSession that honours the configured proxy and HTTP(S)_PROXY env vars."""
    kwargs.setdefault("trust_env", True)
    for k, v in _header_limits().items():
        kwargs.setdefault(k, v)
    if connector is None:
        connector = build_connector()
    return aiohttp.ClientSession(connector=connector, **kwargs)


async def read_body(resp: aiohttp.ClientResponse, cap: int) -> bytes:
    """
    The body, up to `cap` bytes. resp.content.read(n) is NOT this: it returns
    whatever has arrived so far (5.5 KB of a 213 KB Twitch page, live), so a
    capped read must keep reading until the cap or the end of the body.
    """
    buf = bytearray()
    async for chunk in resp.content.iter_chunked(64 * 1024):
        buf += chunk
        if len(buf) >= cap:
            del buf[cap:]
            break
    return bytes(buf)


def describe() -> str:
    """One-line egress description for the CLI header."""
    if _PROXY:
        return f"proxy {redact(_PROXY)}"
    for var in ("ALL_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if os.environ.get(var):
            return f"env {var}={redact(os.environ[var])}"
    return "DIRECT: probes leave from your real IP"
