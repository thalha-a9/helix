"""
Helix as a library (osint.api) and as a local web page (helix --serve).
Both run the same scan as the command line and keep its rules: the control
probe, the unanswered count, the left-out list.
"""

import http.server
import json
import re
import socket
import threading

import pytest
from aiohttp.test_utils import TestClient, TestServer

import osint.checker as ck
from osint import api, i18n, leftout, web


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        kind, _, name = self.path.strip("/").partition("/")
        if kind == "good" and name == "janeroe":
            status, body = 200, b"<html>janeroe - 42 posts</html>"
        elif kind == "any":
            status, body = 200, b"<html>Profile of " + name.encode() + b"</html>"
        elif kind == "wall":
            status, body = 403, b"no"
        else:
            status, body = 404, b"<html>Not Found</html>"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def sites():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    yield {k: {"url": f"{base}/{k.lower()}/{{username}}", "method": "status_code", "found": [200],
               "category": "social", "color": "#fff"} for k in ("Good", "Any", "Wall", "Empty")}
    server.shutdown()


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    monkeypatch.setattr(ck, "RECOVERY_WAIT", {})


# The library

@pytest.mark.asyncio
async def test_a_library_scan_reports_only_confirmed_accounts(sites):
    report = await api.scan("@JaneRoe".lower(), platforms=sites, purpose="  my own\naccounts ")
    assert report["schema"] == "helix.scan.v1" and report["username"] == "janeroe"
    assert report["purpose"] == "my own accounts"
    assert [a["platform"] for a in report["accounts"]] == ["Good"]          # Any finds everyone: discarded
    assert report["accounts"][0]["identity_confidence"] == "LOW"
    s = report["summary"]
    assert (s["attempted"], s["found"], s["answered"], s["unanswered"]) == (4, 1, 2, 2)
    assert {u["platform"] for u in report["unanswered"]} == {"Any", "Wall"}
    assert len(report["results"]) == 4 and not any(k.startswith("_") for r in report["results"] for k in r)
    json.dumps(report)                                                       # plain data all the way down


@pytest.mark.asyncio
async def test_the_library_refuses_bad_names_unknown_sources_and_left_out_names(sites, monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="Invalid characters"):
        await api.scan("jane roe", platforms=sites)
    with pytest.raises(ValueError, match="unknown source"):
        await api.scan("janeroe", sources="builtin,everything", platforms=sites)
    shipped = tmp_path / "left.json"
    shipped.write_text(json.dumps({"schema": leftout.SCHEMA, "tokens": [leftout.token("janeroe")]}))
    monkeypatch.setattr(leftout, "SHIPPED", shipped)
    with pytest.raises(api.LeftOut, match="left-out list"):
        await api.scan("JaneRoe", platforms=sites)


def test_scan_sync_is_the_same_scan(sites):
    report = api.scan_sync("janeroe", platforms={"Good": sites["Good"]})
    assert [a["platform"] for a in report["accounts"]] == ["Good"]


# The words

def test_every_language_has_every_word():
    english = set(i18n.TEXT["en"])
    assert set(i18n.LANGUAGES) == set(i18n.TEXT) == {"en", "hi", "es", "ar", "pt", "ru"}
    for lang, text in i18n.TEXT.items():
        assert set(text) == english, f"{lang} lacks {english - set(text)} or has extra {set(text) - english}"
        assert all(v.strip() for v in text.values())


@pytest.mark.parametrize("header,lang", [
    ("hi-IN,hi;q=0.9,en;q=0.8", "hi"), ("pt-BR", "pt"), ("de-DE,ar;q=0.5", "ar"), ("", "en"), ("zz", "en")])
def test_the_language_follows_the_browser(header, lang):
    assert i18n.pick(header) == lang


def test_the_page_is_right_to_left_in_arabic_and_escapes_its_words():
    page = web.render("ar", "tok")
    assert '<html lang="ar" dir="rtl">' in page and i18n.TEXT["ar"]["scan"] in page
    assert '<html lang="en" dir="ltr">' in web.render("xx", "tok")
    assert not re.search(r"__[A-Z_a-z]+__", page), "a placeholder was left unfilled"
    assert "innerHTML" not in page and page.count("<script") == 2


# The local page

async def fake_scan(username, sources="builtin", purpose="", nsfw=False):
    if username == "listed":
        raise api.LeftOut("listed is on the left-out list")
    if " " in username or not username:
        raise ValueError("Invalid characters (allowed: a-z 0-9 . _ -)")
    return {"schema": api.SCHEMA, "username": username, "purpose": purpose or "not stated",
            "summary": {"attempted": 2, "answered": 1, "found": 1, "unanswered": 1},
            "accounts": [{"platform": "Good", "url": "https://good.example/" + username,
                          "identity_confidence": "LOW"}],
            "unconfirmed": [], "unanswered": [], "left_out": [], "results": [{"platform": "Good"}],
            "sources": sources}


@pytest.fixture
async def client():
    app = web.make_app(token="secret-token", scan=fake_scan)
    async with TestClient(TestServer(app)) as c:
        yield c


@pytest.mark.asyncio
async def test_the_page_is_served_in_the_browsers_language(client):
    r = await client.get("/", headers={"Accept-Language": "es-ES,es;q=0.9"})
    text = await r.text()
    assert r.status == 200 and '<html lang="es"' in text and "secret-token" in text
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"
    assert '<html lang="ru"' in await (await client.get("/?lang=ru")).text()


@pytest.mark.asyncio
async def test_the_api_needs_the_token_and_returns_the_scan(client):
    assert (await client.get("/api/scan?username=janeroe")).status == 403
    assert (await client.get("/api/scan?username=janeroe&token=wrong")).status == 403
    r = await client.get("/api/scan?username=janeroe&token=secret-token&purpose=mine&sources=all")
    body = await r.json()
    assert r.status == 200 and body["accounts"][0]["platform"] == "Good"
    assert body["purpose"] == "mine" and body["sources"] == "all" and "results" not in body
    full = await (await client.get("/api/scan?username=janeroe&token=secret-token&full=1")).json()
    assert full["results"] == [{"platform": "Good"}]


@pytest.mark.asyncio
async def test_the_api_says_why_it_refused(client):
    r = await client.get("/api/scan?username=listed&token=secret-token")
    assert r.status == 403 and (await r.json())["error"] == "refused"
    r = await client.get("/api/scan?username=jane%20roe&token=secret-token")
    assert r.status == 400 and (await r.json())["error"] == "invalid"


@pytest.mark.asyncio
async def test_a_request_for_another_host_name_is_refused(client):
    r = await client.get("/api/scan?username=janeroe&token=secret-token", headers={"Host": "evil.example"})
    assert r.status == 403 and (await r.json())["error"] == "local only"
    assert (await client.get("/", headers={"Host": "evil.example:8765"})).status == 403
