"""
By default Helix names itself in every request: one User-Agent with its name,
version and homepage, never rotated, and no faked TLS fingerprint. A site that
answers only a browser's fingerprint gets no request. Browser mode
(--as-browser, opt-in) asks the fingerprint sites as Chrome, and only them,
and the sealed record says it was on.
"""

import http.server
import socket
import threading

import pytest

import helix_osint
import helix_osint.checker as ck
from helix_osint import api, evidence, leftout


class Handler(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        Handler.seen.append((self.path, self.headers.get("User-Agent")))
        body = b"<html>Not Found</html>"
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    async def no(*a, **k):
        return False
    monkeypatch.setattr(leftout, "refresh", no)
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    monkeypatch.setattr(ck, "RECOVERY_WAIT", {})
    Handler.seen.clear()


def test_the_user_agent_names_helix_its_version_and_homepage():
    ua = ck._headers()["User-Agent"]
    assert ua == f"Helix-OSINT/{helix_osint.__version__} (+https://github.com/thalha-a9/helix)"
    assert "Mozilla" not in ua and "Chrome" not in ua
    assert {ck._headers()["User-Agent"] for _ in range(50)} == {ua}     # never rotated


@pytest.mark.asyncio
async def test_every_request_carries_the_helix_name(base):
    sites = {"A": {"url": f"{base}/a/{{username}}", "method": "status_code", "found": [200],
                   "category": "other", "color": "#fff"}}
    await api.scan("janeroe", platforms=sites)
    assert Handler.seen and all(ua == ck.USER_AGENT for _, ua in Handler.seen)


@pytest.mark.asyncio
async def test_a_site_that_wants_a_browser_fingerprint_gets_no_request_and_counts_as_no_answer(base):
    sites = {"Fp": {"url": f"{base}/fp/{{username}}", "method": "status_code", "found": [200],
                    "category": "other", "color": "#fff", "requires_tls": True}}
    report = await api.scan("janeroe", platforms=sites)
    assert Handler.seen == []                                  # nothing was sent
    assert report["summary"]["unanswered"] == 1 and report["summary"]["found"] == 0
    assert report["unanswered"][0]["why"] == evidence.reason_of(ck.NO_FINGERPRINT)
    assert "fingerprint" in report["unanswered"][0]["why"]


def _plat(base, kind, **extra):
    return {"url": f"{base}/{kind}/{{username}}", "method": "status_code", "found": [200],
            "category": "other", "color": "#fff", **extra}


@pytest.mark.asyncio
async def test_by_default_even_fingerprint_sites_see_helix_own_name(base):
    await api.scan("janeroe", platforms={"Fp": _plat(base, "fp", tls_impersonate=True)})
    assert Handler.seen and all(ua == ck.USER_AGENT for _, ua in Handler.seen)


needs_curl = pytest.mark.skipif(not ck.HAS_CURL_CFFI, reason="curl_cffi not installed (optional)")


@needs_curl
@pytest.mark.asyncio
async def test_browser_mode_asks_only_the_fingerprint_sites_as_chrome(base):
    report = await api.scan("janeroe", as_browser=True, platforms={
        "Fp": _plat(base, "fp", tls_impersonate=True),
        "Wall": _plat(base, "wall", tls_impersonate=True, requires_tls=True),
        "Plain": _plat(base, "plain")})
    agents = {path.split("/")[1]: ua for path, ua in Handler.seen}
    assert agents["fp"] == ck.BROWSER_USER_AGENT and agents["wall"] == ck.BROWSER_USER_AGENT
    assert agents["plain"] == ck.USER_AGENT                     # every other site: Helix's name
    assert report["as_browser"] is True
    assert report["summary"]["answered"] == 3                    # the wall site was asked too
    record, sites = api.record_attempt(report)
    assert record["attempt"]["as_browser"] is True and api.verify_evidence(record, sites) == []


@pytest.mark.asyncio
async def test_a_default_record_does_not_mention_browser_mode(base):
    report = await api.scan("janeroe", platforms={"Plain": _plat(base, "plain")})
    record, _ = api.record_attempt(report)
    assert report["as_browser"] is False and "as_browser" not in record["attempt"]


@pytest.mark.asyncio
async def test_browser_mode_without_curl_cffi_refuses_to_start(base, monkeypatch):
    monkeypatch.setattr(ck, "HAS_CURL_CFFI", False)
    with pytest.raises(RuntimeError, match="helix-osint\\[browser\\]"):
        await api.scan("janeroe", as_browser=True, platforms={"Plain": _plat(base, "plain")})
    assert Handler.seen == []
