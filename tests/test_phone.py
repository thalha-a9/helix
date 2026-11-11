"""
--phone: opt-in, needs a purpose, and never sends anything to the number.
Offline facts, whether found accounts show the number, and (with --breach)
the breach lists.
"""

import argparse
import http.server
import json
import os
import socket
import threading

import pytest

pytest.importorskip("phonenumbers")

from helix_osint import cli as helix                                    # noqa: E402
import helix_osint.checker as ck                      # noqa: E402
from helix_osint import evidence, leftout, phone      # noqa: E402
from helix_osint.adapters import breachdb             # noqa: E402

NUMBER = "+919876543210"


def test_offline_facts_and_the_masked_form():
    r = phone.report(NUMBER)
    assert r["number"] == "+9198xxxxx210" and r["shown_in_full"] is False
    assert (r["valid"], r["country"], r["line_type"], r["country_code"]) == (True, "IN", "mobile", 91)
    assert r["time_zones"] and r["note"] == phone.LEAD_NOTE
    assert phone.report(NUMBER, show=True)["number"] == NUMBER
    assert "mobile; India, IN" in phone.describe(r) and "numbers can move to another carrier" in phone.describe(r)


@pytest.mark.parametrize("text,why", [
    ("9876543210", "write the number with its country code"),
    ("+91", "not a"),
    ("+9198765", "not a possible phone number"),
    ("+91abcdefghij", "not a"),
])
def test_only_a_full_international_number_is_accepted(text, why):
    with pytest.raises(ValueError, match=why):
        phone.report(text)


def test_an_invalid_but_possible_number_is_described_as_such():
    r = phone.report("+11234567890")               # right length, no such area code
    assert r["valid"] is False and "not a valid number" in phone.describe(r)


@pytest.mark.parametrize("text,shown", [
    ("Call me: +91 98765 43210", True), ("tel (098765) 432-10", True), ("9876543210", True),
    ("+91-9876-543-210", True), ("order 19876543210999", False), ("98765 4321", False), ("", False),
])
def test_a_number_on_a_page_is_recognised_however_it_is_written(text, shown):
    assert phone.shown_in(text, phone.parse(NUMBER)) is shown


def test_a_sealed_record_never_holds_the_number_in_full():
    assert evidence._redact_argv(["helix", "--phone", NUMBER, "-u", "x"]) == \
        ["helix", "--phone", "+9198xxxxx210", "-u", "x"]
    assert evidence._redact_argv(["helix", f"--phone={NUMBER}"]) == ["helix", "--phone=+9198xxxxx210"]
    assert evidence._redact_argv(["helix", "--proxy", "http://u:p@h:1"]) == ["helix", "--proxy", "http://***@h:1"]


@pytest.mark.asyncio
async def test_the_breach_lists_are_asked_by_number_only_where_a_source_takes_one(monkeypatch):
    asked = []

    async def fake_query(session, src, identifier):
        asked.append((src["id"], identifier))
        return {"status": "ok", "detail": "", "breaches": [
            {"name": "Facebook", "date": "2019-08-01", "records": 509458528, "data_classes": ["Phone numbers"],
             "domain": "facebook.com", "verified": True}]}

    monkeypatch.setattr(breachdb, "_query", fake_query)
    [v] = await breachdb.check_phone(NUMBER, shown_as="+9198xxxxx210")
    assert asked == [("hibp", NUMBER)]                       # no source is sent a number it cannot take
    assert v["kind"] == "phone" and v["exposed"] is True and v["identifier"] == "+9198xxxxx210"
    assert NUMBER not in json.dumps(v) and "+9198xxxxx210 appears in 1 breach" in v["summary"]
    assert await breachdb.check_phone("9876543210") == []
    assert all("phone" not in s["kinds"] for s in breachdb.SOURCES if s["id"] != "hibp")


# A scan

class Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.rsplit("/", 1)[-1]
        if name == "janeroe" and self.path.startswith("/shows/"):
            status, body = 200, b"<html>janeroe. WhatsApp: +91 98765-43210</html>"
        elif name == "janeroe":
            status, body = 200, b"<html>janeroe - 42 posts</html>"
        else:
            status, body = 404, b"<html>Not Found</html>"
        Site.hits.append(self.path)
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


Site.hits = []


@pytest.fixture
def site(monkeypatch, tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    monkeypatch.setattr(helix, "PLATFORMS", {
        k: {"url": f"{base}/{k.lower()}/{{username}}", "method": "status_code", "found": [200],
            "category": "social", "color": "#fff"} for k in ("Shows", "Plain")})
    Site.hits.clear()
    yield tmp_path
    server.shutdown()


def _args(**kw):
    base = dict(username="janeroe", email=None, providers=False, ai=None,
                all_sources=False, wmn=False, sherlock=False, maigret=False,
                maigret_engine=False, maigret_timeout=30, maigret_top=10, wmn_timeout=30,
                sherlock_timeout=30, no_control=False, wayback=False, crt=False, paste=False,
                breach=False, darkweb=False, holehe=False, pivot=False, pivot_depth=1,
                phash=False, permutations=False, location=None, format="json", report=False,
                email_permute=False, output=None, no_browser=True, nsfw=False,
                proxy=None, tor=False, phone=NUMBER, purpose="my own number", record_attempt=True)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.asyncio
async def test_a_scan_with_a_number_says_which_found_accounts_show_it(site, capsys):
    await helix.run(_args())
    out = capsys.readouterr().out
    assert "Phone" in out and "+9198xxxxx210: mobile; India, IN" in out
    assert "Shown on: Shows" in out and phone.LEAD_NOTE in out and NUMBER not in out
    res = os.path.join(site, "results", "janeroe")
    report = json.load(open([os.path.join(res, f) for f in os.listdir(res) if f.startswith("janeroe_2")][0]))
    assert report["intel"]["phone"]["shown_on"] == ["Shows"]
    assert report["intel"]["phone"]["number"] == "+9198xxxxx210" and report["intel"]["phone"]["breaches"] == []
    for name in os.listdir(res):                       # the full number is in no file the scan wrote
        path = os.path.join(res, name)
        if os.path.isfile(path):
            assert NUMBER not in open(path, encoding="utf-8", errors="ignore").read(), name
    # The number itself was never requested from any site.
    assert not any("9876543210" in h for h in Site.hits)


@pytest.mark.asyncio
async def test_show_number_writes_it_in_full_on_request(site, capsys):
    await helix.run(_args(show_number=True, record_attempt=False))
    assert f"{NUMBER}: mobile" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_number_alone_needs_no_username_and_makes_no_request(site, capsys):
    await helix.run(_args(username=None, record_attempt=False))
    out = capsys.readouterr().out
    assert "+9198xxxxx210: mobile" in out and "Shown on" not in out
    assert Site.hits == [] and os.path.isdir(os.path.join(site, "results", "phone"))


@pytest.mark.asyncio
@pytest.mark.parametrize("kw,message", [
    ({"purpose": None}, "--phone needs --purpose"),
    ({"purpose": "   "}, "--phone needs --purpose"),
    ({"phone": "9876543210"}, "write the number with its country code"),
])
async def test_a_number_is_refused_without_a_purpose_or_a_country_code(site, capsys, kw, message):
    with pytest.raises(SystemExit) as stop:
        await helix.run(_args(**kw))
    assert stop.value.code == 1 and message in capsys.readouterr().out and Site.hits == []


@pytest.mark.asyncio
async def test_a_left_out_number_is_refused_and_not_printed_in_full(site, capsys, monkeypatch, tmp_path):
    shipped = tmp_path / "left.json"
    shipped.write_text(json.dumps({"schema": leftout.SCHEMA, "tokens": [leftout.token(NUMBER)]}))
    monkeypatch.setattr(leftout, "SHIPPED", shipped)
    with pytest.raises(SystemExit) as stop:
        await helix.run(_args())
    out = capsys.readouterr().out
    assert stop.value.code == 3 and "+9198xxxxx210 is on the left-out list" in out and NUMBER not in out
    assert Site.hits == []


def test_all_never_turns_the_phone_part_on_and_me_takes_it(monkeypatch):
    seen = {}

    async def fake_run(args):
        seen.update(vars(args))
    monkeypatch.setattr(helix, "run", fake_run)
    monkeypatch.setattr(helix.sys, "argv", ["helix", "-u", "janeroe", "--all"])
    helix.main()
    assert seen["phone"] is None
    monkeypatch.setattr(helix.sys, "argv", ["helix", "--me", "-u", "janeroe", "--phone", NUMBER])
    helix.main()
    assert seen["phone"] == NUMBER and seen["breach"] and seen["purpose"] == "self-check: my own accounts"
