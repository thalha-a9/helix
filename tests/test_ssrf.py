"""Avatar URLs come from strangers' pages: they must never reach internal addresses."""

import asyncio
import http.server
import socket
import threading

import pytest

from osint import netconfig, phash


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin", "http://localhost:8080/", "http://[::1]/", "http://10.0.0.5/x.png",
    "http://192.168.1.1/a.jpg", "http://172.16.3.4/", "http://169.254.169.254/latest/meta-data/",
    "http://100.64.0.1/", "http://0.0.0.0/", "http://[::ffff:127.0.0.1]/", "http://router.lan/a.png",
    "http://printer.local/", "http://intranet/", "file:///etc/passwd", "ftp://example.com/a.png",
    "gopher://example.com/", "http:///nohost", "", "javascript:alert(1)",
])
def test_internal_and_odd_urls_are_refused(url):
    assert asyncio.run(netconfig.public_url(url)) is not None


@pytest.mark.parametrize("url", ["https://8.8.8.8/a.png", "http://[2606:4700:4700::1111]/a.png"])
def test_public_ip_literals_are_allowed(url):
    assert asyncio.run(netconfig.public_url(url)) is None


def test_hostnames_that_resolve_internally_are_refused(monkeypatch):
    async def fake_resolve(host, port):
        return ["93.184.216.34", "10.1.2.3"]           # one public, one internal: refuse
    monkeypatch.setattr(netconfig, "_resolve", fake_resolve)
    why = asyncio.run(netconfig.public_url("https://evil.example/avatar.png"))
    assert why and "non-public 10.1.2.3" in why


def test_an_explicit_proxy_resolves_names_itself(monkeypatch):
    """--proxy/--tor: resolving locally would leak every avatar host to local DNS."""
    called = []

    async def spy(host, port):
        called.append(host)
        return ["10.0.0.1"]
    monkeypatch.setattr(netconfig, "_resolve", spy)
    netconfig.set_proxy("http://10.0.0.5:3128")
    assert asyncio.run(netconfig.public_url("https://evil.example/a.png")) is None
    assert called == []
    # ...but literal internal addresses are still refused.
    assert asyncio.run(netconfig.public_url("http://127.0.0.1/a.png")) is not None


def test_an_environment_proxy_does_not_skip_the_check(monkeypatch):
    """A local Burp or a corporate proxy from the environment would happily
    fetch localhost or the LAN for us, so names are still checked."""
    async def internal(host, port):
        return ["127.0.0.1"]
    monkeypatch.setattr(netconfig, "_resolve", internal)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    assert asyncio.run(netconfig.public_url("https://evil.example/a.png")) is not None


def test_connections_are_pinned_to_public_addresses():
    """DNS rebinding: the connection itself refuses non-public answers."""
    class Fake:
        def __init__(self, hosts):
            self.hosts = hosts

        async def resolve(self, host, port=0, family=0):
            return [{"hostname": host, "host": h, "port": port, "family": socket.AF_INET,
                     "proto": 0, "flags": 0} for h in self.hosts]

        async def close(self):
            pass

    r = netconfig.PublicOnlyResolver()
    r._inner = Fake(["93.184.216.34", "127.0.0.1"])
    got = asyncio.run(r.resolve("rebind.example", 80))
    assert [i["host"] for i in got] == ["93.184.216.34"]
    r._inner = Fake(["127.0.0.1", "169.254.169.254"])
    with pytest.raises(OSError):
        asyncio.run(r.resolve("rebind.example", 80))


def test_avatar_fetches_use_the_pinned_connector():
    async def go():
        c = netconfig.public_only_connector(limit=1)
        try:
            return isinstance(c._resolver, netconfig.PublicOnlyResolver)
        finally:
            await c.close()
    assert asyncio.run(go()) is True


class _Redirector(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Redirector.hits.append(self.path)
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:1/secret")
        self.end_headers()

    def log_message(self, *a):
        pass


def test_a_redirect_to_an_internal_address_is_not_followed(monkeypatch):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    calls = []
    real = netconfig.public_url

    async def allow_first_hop(url):
        calls.append(url)
        return None if url.startswith(f"http://127.0.0.1:{srv.server_address[1]}") else await real(url)

    monkeypatch.setattr(netconfig, "public_url", allow_first_hop)

    async def go():
        async with netconfig.new_session() as s:
            return await phash._fetch_image(s, f"http://127.0.0.1:{srv.server_address[1]}/a.png")
    try:
        assert asyncio.run(go()) is None
        assert calls[-1] == "http://127.0.0.1:1/secret"     # checked, and refused
        assert _Redirector.hits == ["/a.png"]
    finally:
        srv.shutdown(); srv.server_close()
