"""Regressions from a full-database (~6,000 site) scan on a real network."""

import asyncio
import http.server
import socket
import threading
import time

import aiohttp
import pytest

from osint import checker, netconfig
from osint.platforms import PLATFORMS


# ── DNS: never the aiodns resolver ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_connector_uses_system_resolver_with_dns_cache():
    """aiodns (pulled in by maigret) timed out under thousands of lookups."""
    connector = netconfig.build_connector(limit=5)
    try:
        assert isinstance(connector._resolver, aiohttp.ThreadedResolver)
        assert connector._use_dns_cache and connector._cached_hosts._ttl == 300
    finally:
        await connector.close()


# ── Fast mode for large scans ────────────────────────────────────────────────

class SlowHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        SlowHandler.hits += 1
        time.sleep(1.0)
        try:
            self.send_response(200)
            self.end_headers()
        except OSError:
            pass

    def log_message(self, *args):
        pass


@pytest.fixture
def slow_server():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), SlowHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SlowHandler.hits = 0
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _plat(base):
    return {"url": f"{base}/{{username}}", "method": "status_code", "found": [200],
            "category": "other", "color": "#fff"}


@pytest.mark.asyncio
async def test_fast_mode_makes_a_single_attempt(slow_server, monkeypatch):
    monkeypatch.setattr(checker, "FAST_TIMEOUT", aiohttp.ClientTimeout(total=0.3))
    async with netconfig.new_session() as s:
        r = await checker.check_platform(s, "Slow", _plat(slow_server), "janeroe",
                                         asyncio.Semaphore(1), fast=True)
    assert r["error"] == "timeout"
    assert SlowHandler.hits == 1


@pytest.mark.asyncio
async def test_normal_mode_still_retries(slow_server, monkeypatch):
    monkeypatch.setattr(checker, "TIMEOUT", aiohttp.ClientTimeout(total=0.3))
    monkeypatch.setattr(checker.asyncio, "sleep", _no_sleep)
    async with netconfig.new_session() as s:
        r = await checker.check_platform(s, "Slow", _plat(slow_server), "janeroe",
                                         asyncio.Semaphore(1))
    assert r["error"] == "timeout"
    assert SlowHandler.hits == checker.MAX_RETRIES + 1


_real_sleep = asyncio.sleep


async def _no_sleep(delay, *a, **kw):
    await _real_sleep(0)


@pytest.mark.asyncio
async def test_large_platform_maps_scan_in_fast_mode(monkeypatch):
    seen = []

    async def fake_check(session, name, plat, username, sem, fast=False):
        seen.append(fast)
        return {"platform": name, "found": False}

    monkeypatch.setattr(checker, "check_platform", fake_check)
    big = {f"S{i}": {} for i in range(checker.FAST_SCAN_THRESHOLD + 1)}
    small = {f"S{i}": {} for i in range(10)}

    await checker.check_username("janeroe", platforms=big, control=False)
    assert set(seen) == {True}
    seen.clear()
    await checker.check_username("janeroe", platforms=small, control=False)
    assert set(seen) == {False}


# ── Steam: positive evidence only ────────────────────────────────────────────


def _steam_result():
    return {"platform": "Steam", "url": "https://steamcommunity.com/id/x",
            "category": "gaming", "color": "#fff", "found": False, "error": None,
            "confidence": "low", "bio_links": {}, "og_title": ""}


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    "<html><title>Steam Community :: Error</title>Too many requests</html>",
    "<html><title>Steam Community</title>Sorry! An error was encountered.</html>",
    "<html>Le profil spécifié est introuvable.</html>",
])
async def test_steam_pages_without_profile_data_are_not_found(body):
    r = _steam_result()
    await checker._apply(r, PLATFORMS["Steam"], "x", 200, body,
                         "https://steamcommunity.com/id/x", "https://steamcommunity.com/id/x")
    assert r["found"] is False


@pytest.mark.asyncio
async def test_steam_profile_page_is_found():
    body = ('<html><script>g_rgProfileData = {"url":"https:\\/\\/steamcommunity.com\\/id\\/x\\/",'
            '"steamid":"76561197960287930","personaname":"x"};</script></html>')
    r = _steam_result()
    await checker._apply(r, PLATFORMS["Steam"], "x", 200, body,
                         "https://steamcommunity.com/id/x", "https://steamcommunity.com/id/x")
    assert r["found"] is True


# ── Terminal noise ───────────────────────────────────────────────────────────

def test_network_noise_is_swallowed_but_real_errors_are_not():
    import helix
    calls = []

    class Loop:
        def default_exception_handler(self, ctx):
            calls.append(ctx)

    loop = Loop()
    helix._quiet_network_noise(loop, {"exception": OSError(None, "Timeout while contacting DNS servers")})
    helix._quiet_network_noise(loop, {"exception": asyncio.TimeoutError()})
    assert calls == []

    helix._quiet_network_noise(loop, {"exception": ValueError("real bug")})
    helix._quiet_network_noise(loop, {"message": "no exception attached"})
    assert len(calls) == 2
