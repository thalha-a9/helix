"""
Breach-database coverage (#21, #22, HIBP half of #20).

Live breach APIs are not reachable from CI, so each source is replaced by a
local server replaying the documented response shape. The things that matter:
a breached email is reported (the old adapter read the wrong endpoint and
never did), a clean email says which sources were checked and when, and a
source that could not be reached is never reported as "no breaches".
"""

import http.server
import json
import socket
import threading
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from osint.adapters import breachdb

XON_BREACHED = {
    "BreachMetrics": {},
    "BreachesSummary": {"site": "Adobe;LinkedIn"},
    "ExposedBreaches": {"breaches_details": [
        {"breach": "Adobe", "xposed_date": "2013", "xposed_records": 152445165,
         "xposed_data": "Email addresses;Password hints;Passwords;Usernames",
         "domain": "adobe.com", "verified": "Yes", "industry": "Information Technology"},
        {"breach": "LinkedIn", "xposed_date": "2012", "xposed_records": 164611595,
         "xposed_data": "Email addresses;Passwords", "domain": "linkedin.com", "verified": "Yes"},
    ]},
    "ExposedPastes": None, "PasteMetrics": None,
}

HIBP_BREACHED = [
    {"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com",
     "BreachDate": "2012-05-05", "PwnCount": 164611595,
     "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True,
     "IsFabricated": False, "IsSpamList": False},
    {"Name": "Canva", "Title": "Canva", "Domain": "canva.com", "BreachDate": "2019-05-24",
     "PwnCount": 137272116, "DataClasses": ["Email addresses", "Geographic locations",
                                            "Names", "Passwords", "Usernames"],
     "IsVerified": True, "IsFabricated": False, "IsSpamList": False},
    {"Name": "SpamList", "Title": "Some Spam List", "BreachDate": "2020-01-01",
     "PwnCount": 1, "DataClasses": ["Email addresses"], "IsVerified": False,
     "IsFabricated": False, "IsSpamList": True},
]


class Handler(http.server.BaseHTTPRequestHandler):
    hibp_keys = []

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/xon":
            email = parse_qs(u.query).get("email", [""])[0]
            if email == "pwned@example.com":
                return self._json(200, XON_BREACHED)
            if email == "down@example.com":
                return self._json(503, {"Error": "unavailable"})
            return self._json(404, {"Error": "Not found"})
        if u.path.startswith("/hibp/"):
            Handler.hibp_keys.append(self.headers.get("hibp-api-key"))
            if self.headers.get("hibp-api-key") != "good-key":
                return self._json(401, {"message": "Access denied"})
            email = unquote(u.path[len("/hibp/"):])
            if email == "pwned@example.com":
                return self._json(200, HIBP_BREACHED)
            return self._json(404, None)
        self._json(404, None)

    def _json(self, code, body):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def api(monkeypatch):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    srcs = [dict(s) for s in breachdb.SOURCES]
    srcs[0]["url"] = base + "/xon?email={q}"
    srcs[1]["url"] = base + "/hibp/{q}"
    monkeypatch.setattr(breachdb, "SOURCES", srcs)
    Handler.hibp_keys = []
    yield base
    httpd.shutdown()
    httpd.server_close()


# ── Parsers ───────────────────────────────────────────────────────────────────

def test_xposedornot_parser_reads_breach_details():
    b = breachdb.parse_xposedornot(XON_BREACHED)
    assert [x["name"] for x in b] == ["Adobe", "LinkedIn"]
    assert "Passwords" in b[0]["data_classes"] and b[0]["verified"] is True


@pytest.mark.parametrize("body", [None, {}, {"ExposedBreaches": None}, {"Error": "Not found"},
                                  {"breaches": [["Adobe"]]}, [], "junk"])
def test_xposedornot_parser_tolerates_empty_shapes(body):
    assert breachdb.parse_xposedornot(body) == []


def test_hibp_parser_skips_spam_lists_and_fabricated():
    names = [b["name"] for b in breachdb.parse_hibp(HIBP_BREACHED)]
    assert names == ["LinkedIn", "Canva"]


# ── End to end against the local APIs ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_breached_email_is_reported_with_merged_sources(api, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "good-key")
    [v] = await breachdb.check_identifiers(["Pwned@Example.com"])
    assert v["identifier"] == "pwned@example.com"
    assert v["exposed"] is True
    by = {b["name"]: b for b in v["breaches"]}
    assert set(by) == {"Adobe", "LinkedIn", "Canva"}
    assert by["LinkedIn"]["sources"] == ["XposedOrNot", "Have I Been Pwned"]
    assert by["LinkedIn"]["date"] == "2012-05-05"          # fuller date wins
    assert v["summary"].startswith("pwned@example.com appears in 3 breaches (2012–2019), "
                                   "passwords exposed in 3")
    assert Handler.hibp_keys == ["good-key"]


@pytest.mark.asyncio
async def test_clean_email_names_sources_and_time(api, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "good-key")
    [v] = await breachdb.check_identifiers(["clean@example.com"])
    assert v["exposed"] is False and v["breaches"] == []
    assert "no breaches found in XposedOrNot, Have I Been Pwned" in v["summary"]
    assert v["checked_at"] in v["summary"]


@pytest.mark.asyncio
async def test_hibp_without_key_is_skipped_not_silently_clean(api, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    [v] = await breachdb.check_identifiers(["clean@example.com"])
    hibp = next(s for s in v["sources"] if s["source"] == "Have I Been Pwned")
    assert hibp["status"] == "skipped"
    assert Handler.hibp_keys == []                          # never sent a request
    assert "not checked — Have I Been Pwned: set HIBP_API_KEY" in v["summary"]


@pytest.mark.asyncio
async def test_unreachable_sources_never_read_as_clean(api, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "bad-key")
    [v] = await breachdb.check_identifiers(["down@example.com"])
    assert v["exposed"] is None
    assert "could not be checked" in v["summary"]
    assert "HTTP 503" in v["summary"] and "401" in v["summary"]
    assert "no breaches" not in v["summary"]


@pytest.mark.asyncio
async def test_invalid_and_duplicate_identifiers_are_not_sent(api):
    out = await breachdb.check_identifiers(["not-an-email", "", "a@b.co", "A@B.co"])
    assert [v["identifier"] for v in out] == ["a@b.co"]


def test_format_lines_lists_each_breach():
    v = {"identifier": "x@y.z", "checked_at": "t", "sources": [], "exposed": True,
         "breaches": [{"name": "Adobe", "date": "2013", "records": 1500, "verified": True,
                       "data_classes": ["Passwords"], "sources": ["XposedOrNot"]}]}
    v["summary"] = breachdb.summarise({**v, "sources": [{"source": "XposedOrNot",
                                                         "status": "ok", "detail": ""}]})
    lines = breachdb.format_lines(v)
    assert "Adobe (2013) · 1,500 records · verified" in lines[1]
    assert "exposed: Passwords" in lines[2]
