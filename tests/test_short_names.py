"""
Short names: a site that accepts any short name and refuses longer ones.

Found by a reviewer: the made-up names are padded to 12 random characters so
they cannot collide with a real account, so a site that "finds" every name up
to 11 characters and answers longer ones with 400 "invalid" (or a 404 from a
route that only matches short names) gave every control a clean "not found".
Any short made-up name was then reported as an account. A control of the
searched name's own length closes it.
"""

import asyncio
import http.server
import random
import re
import socket
import string
import threading

import pytest

from bench import benchmark
from osint import evidence
from osint.adapters import maigret_engine as me
from osint.checker import (CONTROL_UNCONFIRMED, DEFAULT_CONTROLS, _extra_controls,
                           check_username, control_username, same_length_control)

LIMIT = 11
REAL = {"jane", "j.roe_9"}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        kind, name = self.path.strip("/").split("/", 1)
        page = b"<html><h1>@" + name.encode() + b"</h1></html>"
        if kind == "honest":
            status, body = (200, page) if name in REAL else (404, b"<html>no such user</html>")
        elif len(name) > LIMIT:
            status, body = ((400, b"<html>invalid username</html>") if kind == "short400"
                            else (404, b"<html>not found</html>"))
        else:
            status, body = 200, page                    # any short name "exists"
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def site():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _plats(base, kinds):
    return {k: {"url": f"{base}/{k}/{{username}}", "method": "status_code", "found": [200],
                "category": "other", "color": "#fff"} for k in kinds}


@pytest.fixture(autouse=True)
def no_wait(monkeypatch):
    from osint import checker
    monkeypatch.setattr(checker, "CONTROL_RETRY_DELAY", 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["short400", "short404"])
async def test_short_made_up_names_are_never_reported(site, kind):
    rng = random.Random(9)
    names = ["".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(3, 10)))
             for _ in range(15)]
    for name in names:
        [r] = await check_username(name, platforms=_plats(site, [kind]))
        assert not r["found"], name
        assert r.get("unconfirmed") and r["error"] == CONTROL_UNCONFIRMED


@pytest.mark.asyncio
async def test_real_short_accounts_on_an_honest_site_are_still_found(site):
    for name in REAL:
        [r] = await check_username(name, platforms=_plats(site, ["honest"]))
        assert r["found"] and not r.get("unconfirmed"), name


@pytest.mark.asyncio
async def test_more_controls_still_find_real_accounts(site):
    [r] = await check_username("jane", platforms=_plats(site, ["honest"]), controls=8)
    assert r["found"]


@pytest.mark.parametrize("name", ["jack", "a", "j.roe_9", "4tj", "x-y", "ab_cd.ef"])
def test_same_length_control_keeps_length_and_punctuation(name):
    for _ in range(20):
        c = same_length_control(name)
        assert len(c) == len(name)
        assert re.sub(r"[A-Za-z0-9]", "", c) == re.sub(r"[A-Za-z0-9]", "", name)
        assert [ch.isdigit() for ch in c[:1]] == [ch.isdigit() for ch in name[:1]]


def test_short_names_get_same_length_controls():
    short, long_ = "jack", "4tj4jneu4byr"
    names, same = _extra_controls(short, control_username(short), DEFAULT_CONTROLS)
    assert same and len(names) == 1 and len(names[0]) == len(short)
    names, same = _extra_controls(long_, control_username(long_), DEFAULT_CONTROLS)
    assert not same and len(names) == 1 and len(names[0]) == len(long_)
    names, same = _extra_controls(long_, control_username(long_), 5)
    assert len(names) == 3 and all(len(n) == len(long_) for n in names)


def test_one_letter_names_do_not_loop_forever():
    names, same = _extra_controls("a", control_username("a"), 40)
    assert same and len(set(names)) == len(names) <= 25


def test_unconfirmed_has_its_own_reason_in_the_evidence():
    assert evidence.reason_of(CONTROL_UNCONFIRMED) == \
        "unconfirmed: a same-length made-up name was also found"


@pytest.mark.asyncio
async def test_maigret_engine_leads_on_short_catch_alls_are_unconfirmed(site):
    lead = {"platform": "X", "url": f"{site}/short400/jane", "found": True,
            "_page_text": "<html><h1>@jane</h1></html>"}
    ctrls = (control_username("jane"), control_username("jane", keep_leading_digits=True),
             same_length_control("jane"))
    from osint import netconfig
    async with netconfig.new_session() as session:
        await me._control_check(session, lead, "jane", ctrls, asyncio.Semaphore(2))
    assert not lead["found"] and lead.get("unconfirmed")


def test_benchmark_has_short_catch_alls_and_reports_none():
    report = benchmark.run(sites=60, seed=4, catchall_frac=0.05, short_catchall_frac=0.15,
                           latency_ms=0, control=True)
    best = report["best"]
    assert best["catchall_sites"] > 0 and best["unconfirmed"] > 0
    assert best["false_positives"] == 0 and best["recall"] == 1.0


def test_unconfirmed_sites_are_listed_in_the_json_report(tmp_path):
    import json
    from osint.report import save_json
    results = [{"platform": "A", "found": True, "url": "u"},
               {"platform": "B", "found": False, "error": CONTROL_UNCONFIRMED, "unconfirmed": True},
               {"platform": "C", "found": False}]
    data = json.load(open(save_json("jack", results, str(tmp_path))))
    assert data["summary"]["unconfirmed"] == 1
    assert [r["platform"] for r in data["unconfirmed"]] == ["B"]
