"""
Control probe — every hit is re-checked with a username that cannot exist.

Regression from a live scan: logged out, Facebook and Instagram serve the same
login-wall page for any name, so a nonexistent username was reported "found".
A platform that also finds the control name proves nothing and is discarded.
"""

import http.server
import socket
import threading

import pytest

from osint.adapters import maigret_engine as me
from osint.checker import CONTROL_ERROR, check_username, control_username, validate_username

CATCH_ALL = (b'<html><head><meta property="og:title" content="Log in or sign up">'
             b'</head><body>See posts, photos and more. Log in to continue.</body></html>')


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path.startswith("/wall/") or path.startswith("/any/"):
            status, body = 200, CATCH_ALL                        # same page for any name
        elif path.startswith("/echo/"):
            name = path.rsplit("/", 1)[-1].encode()
            status, body = 200, b"<html><head><title>Profile of " + name + \
                b"</title></head><body>Welcome to the profile of " + name + b"</body></html>"
        elif path == "/real/janeroe":
            status, body = 200, (b'<html><head><meta property="og:title" content="Jane Roe">'
                                 b'</head><body>Jane Roe - 42 posts, joined 2019</body></html>')
        else:
            status, body = 404, b"<html><body>Sorry, nobody by that name.</body></html>"
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def base():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def plat(base, prefix, **kw):
    d = {"url": f"{base}/{prefix}/{{username}}", "method": "text_not_present",
         "not_found_text": "Page Not Found", "category": "social", "color": "#fff"}
    d.update(kw)
    return d


@pytest.fixture
def platforms(base):
    return {
        "Discriminating": plat(base, "real"),
        "LoginWall":      plat(base, "wall"),   # Facebook/Instagram when logged out
        "Absent":         plat(base, "gone"),
    }


def by_name(results):
    return {r["platform"]: r for r in results}


# ── Control username ─────────────────────────────────────────────────────────

def test_control_username_is_valid_and_random():
    names = {control_username() for _ in range(50)}
    assert len(names) == 50
    for n in names:
        assert validate_username(n)[0]
        assert len(n) == 12 and n[0].isalpha() and n == n.lower()


# ── Checker path (builtin + WMN/Sherlock/Maigret databases) ──────────────────

@pytest.mark.asyncio
async def test_catch_all_platform_is_discarded(platforms):
    r = by_name(await check_username("janeroe", platforms=platforms))
    assert r["LoginWall"]["found"] is False
    assert r["LoginWall"]["error"] == CONTROL_ERROR
    assert r["LoginWall"]["control_failed"] is True


@pytest.mark.asyncio
async def test_discriminating_platform_is_kept(platforms):
    r = by_name(await check_username("janeroe", platforms=platforms))
    assert r["Discriminating"]["found"] is True
    assert not r["Discriminating"].get("control_failed")


@pytest.mark.asyncio
async def test_absent_profile_stays_absent(platforms):
    r = by_name(await check_username("janeroe", platforms=platforms))
    assert r["Absent"]["found"] is False
    assert not r["Absent"].get("control_failed")


@pytest.mark.asyncio
async def test_nonexistent_username_finds_nothing(platforms):
    """The live-scan regression: a made-up name must come back empty."""
    results = await check_username("zzqx9nonexist42k", platforms=platforms)
    assert [r["platform"] for r in results if r["found"]] == []


@pytest.mark.asyncio
async def test_control_can_be_disabled(platforms):
    r = by_name(await check_username("janeroe", platforms=platforms, control=False))
    assert r["LoginWall"]["found"] is True


# ── Page similarity (Maigret engine leads) ───────────────────────────────────

def test_same_page_with_only_the_name_changed_looks_same():
    a = "<title>Profile of janeroe</title><body>Welcome to the profile of janeroe</body>"
    b = "<title>Profile of xq7k2m9p4r1s</title><body>Welcome to the profile of xq7k2m9p4r1s</body>"
    assert me.looks_same(a, b, "janeroe", "xq7k2m9p4r1s")


def test_real_profile_and_not_found_page_differ():
    a = "<title>Jane Roe</title><body>Jane Roe - 42 posts, joined 2019, lives in Wellington</body>"
    b = "<title>Not found</title><body>Sorry, nobody by that name.</body>"
    assert not me.looks_same(a, b, "janeroe", "xq7k2m9p4r1s")


def test_empty_pages_never_look_same():
    assert not me.looks_same("", "", "janeroe", "x")


@pytest.mark.asyncio
async def test_engine_lead_on_catch_all_url_is_discarded(base):
    leads = me.parse_report({
        "EchoSite": {"url_user": f"{base}/echo/janeroe", "is_similar": False,
                     "status": {"status": "Claimed", "tags": []}},
        "RealSite": {"url_user": f"{base}/real/janeroe", "is_similar": False,
                     "status": {"status": "Claimed", "tags": []}},
    }, "janeroe")
    out = {r["platform"]: r for r in await me.reprobe_leads(leads, username="janeroe")}
    assert out["EchoSite"]["found"] is False
    assert out["EchoSite"]["error"] == CONTROL_ERROR
    assert out["RealSite"]["found"] is True


@pytest.mark.asyncio
async def test_engine_lead_with_id_based_url_skips_control(base):
    leads = me.parse_report({
        "IdSite": {"url_user": f"{base}/any/12345", "is_similar": False,
                   "status": {"status": "Claimed", "tags": []}},
    }, "janeroe")
    [r] = await me.reprobe_leads(leads, username="janeroe")
    assert not r.get("control_failed")


# ── Maigret database templates ───────────────────────────────────────────────

def test_maigret_placeholders_are_filled():
    from osint.adapters.maigret_adapter import _translate
    r = _translate("X", {"url": "{urlMain}{urlSubpath}/u/{username}",
                         "urlMain": "https://x.example", "urlSubpath": "/forum",
                         "absenceStrs": ["nope"]})
    assert r["url"] == "https://x.example/forum/u/{username}"


def test_maigret_entry_with_unfillable_placeholder_is_dropped():
    """Regression: Rutracker's {urlMain} had no value and was requested literally."""
    from osint.adapters.maigret_adapter import _translate
    assert _translate("Rutracker", {"url": "{urlMain}forum/profile.php?u={username}"}) is None
