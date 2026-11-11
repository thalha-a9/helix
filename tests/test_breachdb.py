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

from helix_osint.adapters import breachdb

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


# LeakCheck names breaches by domain; these two are the same breaches as above.
LC_BREACHED = {"success": True, "found": 2, "fields": ["email", "password", "username"],
               "sources": [{"name": "LinkedIn.com", "date": "2012-05"},
                           {"name": "Adobe.com", "date": "2013-10"}]}
LC_ONLY = {"success": True, "found": 1, "fields": ["email", "phone"],
           "sources": [{"name": "Badoo.com", "date": "2016-06"}]}


class Handler(http.server.BaseHTTPRequestHandler):
    hibp_keys = []
    leakcheck_queries = []

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
        if u.path == "/leakcheck":
            q = parse_qs(u.query).get("check", [""])[0]
            Handler.leakcheck_queries.append(q)
            if q == breachdb.leakcheck_hash("pwned@example.com"):
                return self._json(200, LC_BREACHED)
            if q == breachdb.leakcheck_hash("lc-only@example.com"):
                return self._json(200, LC_ONLY)
            if q == breachdb.leakcheck_hash("down@example.com"):
                return self._json(200, {"success": False, "error": "Too many requests"})
            return self._json(200, {"success": False, "error": "Not found"})
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
    local = {"xposedornot": "/xon?email={q}", "hibp": "/hibp/{q}", "leakcheck": "/leakcheck?check={q}"}
    srcs = [dict(s, url=base + local[s["id"]], min_interval=0) for s in breachdb.SOURCES]
    assert {s["id"] for s in srcs} == set(local)   # a new source must get a local stand-in
    monkeypatch.setattr(breachdb, "SOURCES", srcs)
    Handler.hibp_keys = []
    Handler.leakcheck_queries = []
    yield base
    httpd.shutdown()
    httpd.server_close()


# Parsers

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


# End to end against the local APIs

@pytest.mark.asyncio
async def test_breached_email_is_reported_with_merged_sources(api, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "good-key")
    [v] = await breachdb.check_identifiers(["Pwned@Example.com"])
    assert v["identifier"] == "pwned@example.com"
    assert v["exposed"] is True
    by = {b["name"]: b for b in v["breaches"]}
    assert set(by) == {"Adobe", "LinkedIn", "Canva"}
    # LeakCheck's "LinkedIn.com" and "Adobe.com" are the same breaches, not new ones
    assert by["LinkedIn"]["sources"] == ["XposedOrNot", "Have I Been Pwned", "LeakCheck"]
    assert by["Adobe"]["sources"] == ["XposedOrNot", "LeakCheck"]
    assert by["LinkedIn"]["date"] == "2012-05-05"          # fuller date wins
    assert v["summary"].startswith("pwned@example.com appears in 3 breaches (2012 to 2019), "
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
    assert "not checked: Have I Been Pwned: set HIBP_API_KEY" in v["summary"]


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
    assert "Adobe (2013) | 1,500 records | verified" in lines[1]
    assert "exposed: Passwords" in lines[2]


def test_api_text_is_stripped_of_control_characters():
    b = breachdb.parse_hibp([{"Name": "Evil\x1b[2J", "BreachDate": "2020-01-01",
                              "DataClasses": ["Passwords\x07", "\x1b"]}])
    assert b[0]["name"] == "Evil [2J" and b[0]["data_classes"] == ["Passwords"]


# Real naming differences between XposedOrNot and HIBP (from the live catalogues).
@pytest.mark.parametrize("xon,hibp", [
    ({"breach": "Condo", "xposed_date": "2019", "domain": "condo.com"},
     {"Name": "CondoCom", "Title": "Condo.com", "Domain": "condo.com", "BreachDate": "2019-06-01"}),
    ({"breach": "Verifications", "xposed_date": "2019", "domain": "verifications.io"},
     {"Name": "VerificationsIO", "Title": "Verifications.io", "Domain": "verifications.io",
      "BreachDate": "2019-02-25"}),
    ({"breach": "AdultFriendFinder", "xposed_date": "2015", "domain": "x.invalid"},
     {"Name": "AdultFriendFinder", "Title": "Adult FriendFinder (2015)", "Domain": "",
      "BreachDate": "2015-05-21"}),
])
def test_same_breach_under_different_names_is_merged(xon, hibp):
    m = breachdb._merge([("XposedOrNot", breachdb.parse_xposedornot(
                             {"ExposedBreaches": {"breaches_details": [xon]}})),
                         ("Have I Been Pwned", breachdb.parse_hibp([hibp]))])
    assert len(m) == 1 and m[0]["sources"] == ["XposedOrNot", "Have I Been Pwned"]
    assert "aliases" not in m[0]


def test_same_domain_different_years_stay_separate():
    m = breachdb._merge([("Have I Been Pwned", breachdb.parse_hibp([
        {"Name": "Twitter", "Title": "Twitter", "Domain": "twitter.com", "BreachDate": "2022-01-01"},
        {"Name": "Twitter200M", "Title": "Twitter (200M)", "Domain": "twitter.com",
         "BreachDate": "2021-01-01"}]))])
    assert len(m) == 2


def test_duplicate_within_one_source_counts_once(api, monkeypatch):
    dup = {"breach": "Apollo", "xposed_date": "2018", "domain": "apollo.io", "xposed_data": "Names"}
    assert len(breachdb._merge([("X", breachdb.parse_xposedornot(
        {"ExposedBreaches": {"breaches_details": [dup, dict(dup)]}}))])) == 1


def test_found_breaches_still_name_unchecked_sources():
    v = {"identifier": "a@b.co", "checked_at": "t",
         "sources": [{"source": "XposedOrNot", "status": "ok", "detail": ""},
                     {"source": "Have I Been Pwned", "status": "error",
                      "detail": "API key rejected (401)"}],
         "breaches": [{"name": "Adobe", "date": "2013", "data_classes": [], "sources": ["XposedOrNot"]}]}
    s = breachdb.summarise(v)
    assert "appears in 1 breach (2013)" in s and "not checked: Have I Been Pwned: API key rejected" in s


def test_console_listing_is_capped():
    v = {"summary": "s", "breaches": [{"name": f"B{i}", "date": "2020", "data_classes": [],
                                       "sources": ["X"]} for i in range(20)]}
    lines = breachdb.format_lines(v, limit=8)
    assert sum(1 for line in lines if line.startswith("  - ")) == 8
    assert "+12 older breach(es)" in lines[-1]
    assert sum(1 for line in breachdb.format_lines(v) if line.startswith("  - ")) == 20


# LeakCheck

def test_leakcheck_is_sent_a_hash_never_the_address(api):
    import asyncio
    asyncio.run(breachdb.check_identifiers(["pwned@example.com", "nobody@example.com"]))
    assert Handler.leakcheck_queries == [breachdb.leakcheck_hash("pwned@example.com"),
                                         breachdb.leakcheck_hash("nobody@example.com")]
    assert all("@" not in q and len(q) == 24 for q in Handler.leakcheck_queries)


def test_leakcheck_hash_matches_its_documented_example():
    assert breachdb.leakcheck_hash("example@example.com") == "31c5543c1734d25c7206f5fd"


@pytest.mark.asyncio
async def test_leakcheck_only_breach_is_reported_with_its_data_types(api, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    [v] = await breachdb.check_identifiers(["lc-only@example.com"])
    assert v["exposed"] is True
    [b] = v["breaches"]
    assert b["name"] == "Badoo.com" and b["sources"] == ["LeakCheck"]
    assert b["data_classes"] == []            # its field list is not per breach
    lines = breachdb.format_lines(v)
    assert any("LeakCheck lists these data types across its 1 match(es), not per breach: "
               "email, phone" in line for line in lines)


@pytest.mark.asyncio
async def test_leakcheck_not_found_is_clean_and_other_errors_are_not(api, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "good-key")
    [clean] = await breachdb.check_identifiers(["nobody@example.com"])
    lc = next(s for s in clean["sources"] if s["source"] == "LeakCheck")
    assert lc["status"] == "ok" and "LeakCheck" in clean["summary"]
    [down] = await breachdb.check_identifiers(["down@example.com"])
    lc = next(s for s in down["sources"] if s["source"] == "LeakCheck")
    assert lc["status"] == "error" and lc["detail"] == "Too many requests"


def test_leakcheck_parser_keeps_names_dates_and_nothing_else():
    b = breachdb.parse_leakcheck({"success": True, "found": 1, "fields": ["password"],
                                  "sources": [{"name": "Some.Site", "date": "2020-01",
                                               "password": "hunter2"}]})
    assert b == [{"name": "Some.Site", "date": "2020-01", "records": None, "data_classes": [],
                  "domain": "some.site", "verified": False, "aliases": ["Some"]}]
    assert breachdb.parse_leakcheck({"success": False, "error": "Not found"}) == []


@pytest.mark.asyncio
async def test_leakcheck_is_paced_to_one_request_a_second(monkeypatch):
    import time
    calls = []
    src = {"id": "pace-test", "min_interval": 0.3}
    breachdb._LAST_CALL.pop("pace-test", None)
    for _ in range(3):
        await breachdb._pace(src)
        calls.append(time.monotonic())
    assert calls[1] - calls[0] >= 0.29 and calls[2] - calls[1] >= 0.29
