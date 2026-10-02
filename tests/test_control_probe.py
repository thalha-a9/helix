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
from osint.checker import (CONTROL_ERROR, CONTROL_INCONCLUSIVE, RECHECK_ERROR, check_username,
                           control_username, definitive_negative, validate_username)

CATCH_ALL = (b'<html><head><meta property="og:title" content="Log in or sign up">'
             b'</head><body>See posts, photos and more. Log in to continue.</body></html>')
FLAKY = {"n": 0}
RETRY = {"n": 0}
ONEOFF = {"n": 0}


def _login_wall(name):
    # Like facebook.com/<name> logged out: same wall for any name, name echoed.
    return (b'<html><head><meta property="og:title" content="Log in or sign up">'
            b'<link rel="canonical" href="/' + name + b'"></head>'
            b'<body>See posts, photos and more. Log in to continue.</body></html>')


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path.startswith("/wall/"):
            status, body = 200, _login_wall(path.rsplit("/", 1)[-1].encode())
        elif path.startswith("/any/"):
            status, body = 200, CATCH_ALL                        # same page for any name
        elif path.startswith("/blocked/"):
            # Real profile for janeroe, but random names keep getting rate-limited.
            if path.endswith("/janeroe"):
                status, body = 200, b"<html>janeroe - 42 posts</html>"
            else:
                status, body = 429, b"<html>Too many requests</html>"
        elif path.startswith("/oneoff/"):
            # Catch-all page naming whoever is asked for — except one request
            # for a random name that happened to hit a 500.
            name = path.rsplit("/", 1)[-1].encode()
            if not path.endswith("/janeroe"):
                ONEOFF["n"] += 1
            if not path.endswith("/janeroe") and ONEOFF["n"] == 1:
                status, body = 500, b"<html>Internal Server Error</html>"
            else:
                status, body = 200, b"<html>Profile of " + name + b"</html>"
        elif path.startswith("/retry/"):
            # Profile is real; the first random-name request is rate-limited.
            if path.endswith("/janeroe"):
                status, body = 200, b"<html>janeroe - 42 posts</html>"
            else:
                RETRY["n"] += 1
                status, body = (429, b"slow down") if RETRY["n"] == 1 else \
                    (404, b"<html><body>Page Not Found</body></html>")
        elif path.startswith("/flaky/"):
            # Overloaded during the scan: a 200 error page once, then honest 404s.
            FLAKY["n"] += 1
            if path.endswith("/janeroe") and FLAKY["n"] == 1:
                status, body = 200, b"<html>Service busy for janeroe, retry</html>"
            else:
                status, body = 404, b"<html><body>Page Not Found</body></html>"
        elif path.startswith("/echo/"):
            name = path.rsplit("/", 1)[-1].encode()
            status, body = 200, b"<html><head><title>Profile of " + name + \
                b"</title></head><body>Welcome to the profile of " + name + b"</body></html>"
        elif path == "/real/janeroe":
            status, body = 200, (b'<html><head><meta property="og:title" content="Jane Roe (@janeroe)">'
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



# ── Inconclusive controls and non-reproducing hits (live --all scan lessons) ─

@pytest.mark.asyncio
async def test_control_that_stays_rate_limited_is_inconclusive(base, monkeypatch):
    import osint.checker as ck
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    r = by_name(await check_username("janeroe", platforms={"Blocked": plat(base, "blocked")}))
    assert r["Blocked"]["found"] is False
    assert r["Blocked"]["error"] == CONTROL_INCONCLUSIVE


@pytest.mark.asyncio
async def test_hit_that_does_not_reproduce_is_dropped(base):
    FLAKY["n"] = 0
    r = by_name(await check_username("janeroe", platforms={"Flaky": plat(base, "flaky")}))
    assert r["Flaky"]["found"] is False
    assert r["Flaky"]["error"] == RECHECK_ERROR


@pytest.mark.parametrize("control,method,ok", [
    ({"found": False, "status_code": 404}, "status_code", True),
    ({"found": False, "status_code": 400}, "status_code", True),     # Bluesky API
    ({"found": False, "status_code": 410}, "status_code", True),
    ({"found": False, "status_code": 403}, "status_code", True),     # jAlbum "Account not found"
    ({"found": False, "status_code": 500}, "status_code", True),     # Eintracht forum
    ({"found": False, "status_code": 204}, "text_present", True),    # Filmweb
    ({"found": False, "status_code": 502}, "status_code", False),
    ({"found": False, "status_code": 522}, "status_code", False),    # Cloudflare edge
    ({"found": False, "status_code": 999}, "text_not_present", False),  # LinkedIn
    ({"found": False, "status_code": 429}, "text_not_present", False),
    ({"found": False, "status_code": 202}, "status_code", False),    # slrpnk.net
    ({"found": False, "status_code": 503}, "og_meta", False),
    ({"found": False, "status_code": None}, "og_meta", False),
    ({"found": False, "status_code": 200}, "text_not_present", True),
    ({"found": False, "status_code": 200}, "text_present", True),    # Steam, GitLab API
    ({"found": False, "status_code": 200}, "status_code", False),
    ({"found": False, "status_code": None, "error": "timeout"}, "og_meta", False),
    ({"found": True, "status_code": 200}, "og_meta", False),
])
def test_definitive_negative(control, method, ok):
    assert definitive_negative(control, {"method": method}) is ok



@pytest.mark.asyncio
async def test_rate_limited_control_is_retried_once(base, monkeypatch):
    import osint.checker as ck
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    RETRY["n"] = 0
    r = by_name(await check_username("janeroe", platforms={"Retry": plat(base, "retry")}))
    assert r["Retry"]["found"] is True and RETRY["n"] == 3   # 429, retry 404, 2nd name 404


@pytest.mark.asyncio
async def test_one_off_error_for_the_random_name_is_not_proof(base, monkeypatch):
    """Live --all lesson: under load a catch-all site answered the control with a
    one-off 500, which looked like 'no such user'. Two random names must agree."""
    import osint.checker as ck
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    ONEOFF["n"] = 0
    r = by_name(await check_username("janeroe", platforms={"OneOff": plat(base, "oneoff")}))
    assert r["OneOff"]["found"] is False
    assert r["OneOff"]["error"] in (CONTROL_ERROR, CONTROL_INCONCLUSIVE)
