import os

import aiohttp
import pytest

from osint import netconfig


def test_no_proxy_by_default():
    assert netconfig.get_proxy() is None
    assert netconfig.request_kwargs() == {}
    assert netconfig.curl_kwargs() == {}
    assert "DIRECT" in netconfig.describe()


def test_http_proxy_is_passed_per_request():
    netconfig.set_proxy("http://10.0.0.5:3128")
    assert netconfig.request_kwargs() == {"proxy": "http://10.0.0.5:3128"}
    assert netconfig.curl_kwargs()["proxies"]["https"] == "http://10.0.0.5:3128"


def test_http_proxy_exported_to_env_for_third_party_sessions():
    netconfig.set_proxy("http://10.0.0.5:3128")
    assert os.environ["HTTPS_PROXY"] == "http://10.0.0.5:3128"
    assert os.environ["http_proxy"] == "http://10.0.0.5:3128"


@pytest.mark.skipif(not netconfig.HAS_SOCKS, reason="aiohttp-socks not installed")
@pytest.mark.asyncio
async def test_socks_proxy_applies_at_connector_not_per_request():
    netconfig.set_proxy("socks5://127.0.0.1:9050")
    assert netconfig.is_socks()
    # SOCKS cannot ride a per-request kwarg — it must come from the connector.
    assert netconfig.request_kwargs() == {}
    connector = netconfig.build_connector()
    try:
        assert type(connector) is not aiohttp.TCPConnector
    finally:
        await connector.close()


@pytest.mark.skipif(not netconfig.HAS_SOCKS, reason="aiohttp-socks not installed")
def test_socks_proxy_not_leaked_into_env():
    netconfig.set_proxy("socks5://127.0.0.1:9050")
    # aiohttp cannot honour socks:// from env; exporting it would silently
    # produce direct connections instead of failing loudly.
    assert "HTTPS_PROXY" not in os.environ


@pytest.mark.asyncio
async def test_plain_connector_when_no_proxy():
    connector = netconfig.build_connector(limit=5)
    try:
        assert type(connector) is aiohttp.TCPConnector
    finally:
        await connector.close()


@pytest.mark.parametrize("bad", [
    "ftp://1.2.3.4:21",
    "gopher://example.com",
    "http://",
    "not-a-url",
])
def test_invalid_proxy_rejected(bad):
    with pytest.raises(ValueError):
        netconfig.set_proxy(bad)
    assert netconfig.get_proxy() is None


@pytest.mark.parametrize("good", [
    "http://10.0.0.5:3128",
    "https://proxy.example.com:8443",
    "http://user:pass@10.0.0.5:3128",
])
def test_valid_http_proxies_accepted(good):
    assert netconfig.set_proxy(good) == good


def test_clearing_proxy():
    netconfig.set_proxy("http://10.0.0.5:3128")
    netconfig.set_proxy(None)
    assert netconfig.get_proxy() is None
    assert netconfig.request_kwargs() == {}


def test_credentials_redacted():
    netconfig.set_proxy("http://alice:hunter2@10.0.0.5:3128")
    described = netconfig.describe()
    assert "hunter2" not in described
    assert "alice" not in described
    assert "10.0.0.5:3128" in described


def test_redact_leaves_credential_free_urls_intact():
    assert netconfig.redact("socks5://127.0.0.1:9050") == "socks5://127.0.0.1:9050"
    assert netconfig.redact(None) == ""


def test_describe_reports_env_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.9:8080")
    assert "10.0.0.9:8080" in netconfig.describe()


@pytest.mark.asyncio
async def test_new_session_trusts_env():
    session = netconfig.new_session()
    try:
        assert session.trust_env is True
    finally:
        await session.close()


def test_tor_shorthand_is_a_socks_url():
    assert netconfig.is_socks(netconfig.TOR_PROXY)
    assert netconfig.TOR_PROXY.endswith(":9050")


@pytest.mark.parametrize("given,curl", [
    ("socks5://127.0.0.1:9050", "socks5h://127.0.0.1:9050"),
    ("socks4://127.0.0.1:1080", "socks4a://127.0.0.1:1080"),
    ("socks5h://127.0.0.1:9050", "socks5h://127.0.0.1:9050"),
    ("http://10.0.0.5:3128", "http://10.0.0.5:3128"),
])
def test_curl_resolves_names_at_the_proxy(given, curl):
    """Live: with socks5:// curl sent bare IPs through the proxy — local DNS saw every platform."""
    netconfig.set_proxy(given)
    assert netconfig.curl_kwargs()["proxies"]["https"] == curl


@pytest.mark.asyncio
async def test_socks_connector_resolves_remotely():
    netconfig.set_proxy("socks5://127.0.0.1:9050")
    c = netconfig.build_connector()
    try:
        assert c._rdns is True
    finally:
        await c.close()


class _SlowBody(__import__("http.server").server.BaseHTTPRequestHandler):
    """Sends a large body in small, delayed pieces — like a real page over the network."""
    def do_GET(self):
        import time
        body = b"<html>" + b"x" * 200_000 + b"MARKER</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        for i in range(0, len(body), 4096):
            self.wfile.write(body[i:i + 4096]); self.wfile.flush(); time.sleep(0.001)

    def log_message(self, *a):
        pass


@pytest.fixture
def slow_server():
    import socket, threading, http.server
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _SlowBody)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}/"
    httpd.shutdown(); httpd.server_close()


@pytest.mark.asyncio
async def test_read_body_reads_to_the_end_not_the_first_chunk(slow_server):
    async with netconfig.new_session() as s:
        async with s.get(slow_server) as r:
            body = await netconfig.read_body(r, 512 * 1024)
    assert body.endswith(b"MARKER</html>")


@pytest.mark.asyncio
async def test_read_body_respects_the_cap(slow_server):
    async with netconfig.new_session() as s:
        async with s.get(slow_server) as r:
            body = await netconfig.read_body(r, 10_000)
    assert len(body) == 10_000
