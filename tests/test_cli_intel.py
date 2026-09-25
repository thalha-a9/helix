"""
Whole-pipeline check for #20–#23: a real helix.run() against local stand-ins
for a profile site, the breach APIs and Ahmia. The subject's profile declares
an employer; the supplied email is breached; Ahmia names the handle.
"""

import argparse
import glob
import http.server
import json
import os
import socket
import threading

import pytest

import helix

from test_breachdb import api                     # noqa: F401  (fixture)
from test_robin import ahmia, ONION_A             # noqa: F401  (fixture)

PROFILE = (b'<html><head><meta property="og:title" content="Jane Roe (@janeroe)">'
           b'<meta property="og:description" content="Senior engineer at Globex. Ex-Initech.">'
           b'</head><body>janeroe</body></html>')


class Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/u/janeroe"
        body = PROFILE if ok else b"<html>Sorry, this page does not exist</html>"
        self.send_response(200 if ok else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def site():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Site)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _args(tmp, **kw):
    base = dict(username="janeroe", email="pwned@example.com", providers=False, ai=None,
                all_sources=False, wmn=False, sherlock=False, maigret=False,
                maigret_engine=False, maigret_timeout=30, maigret_top=10, wmn_timeout=30,
                sherlock_timeout=30, no_control=True, wayback=False, crt=False, paste=False,
                breach=True, darkweb=True, holehe=False, pivot=False, pivot_depth=1,
                phash=False, permutations=False, location=None, format="all", report=True,
                email_permute=False, output=None, no_browser=True, nsfw=False,
                proxy=None, tor=False)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.asyncio
async def test_full_run_reports_relationships_breaches_and_onion_leads(
        site, api, ahmia, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HIBP_API_KEY", "good-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(helix, "PLATFORMS", {"Exampleweb": {
        "url": site + "/u/{username}", "method": "status_code", "found": [200],
        "category": "social", "color": "#fff"}})

    async def no_email_scan(email):
        return []
    monkeypatch.setattr(helix, "check_email", no_email_scan)

    await helix.run(_args(tmp_path))
    out = capsys.readouterr().out

    assert "works at→ Globex" in out and "formerly at→ Initech" in out
    assert "pwned@example.com appears in 3 breaches (2012–2019)" in out
    assert "'janeroe': 1 lead(s)" in out and ONION_A in out

    res = os.path.join(tmp_path, "results", "janeroe")
    data = json.load(open(glob.glob(os.path.join(res, "janeroe_*.json"))[0]))
    intel = data["intel"]
    assert {e["target"] for e in intel["relationships"]} == {"Globex", "Initech"}
    assert all(e["confidence"] == "LOW" for e in intel["relationships"])   # username match only
    assert intel["breaches"][0]["exposed"] is True
    assert intel["darkweb"]["ahmia"][0]["hits"][0]["onion"] == ONION_A

    csv_text = open(glob.glob(os.path.join(res, "janeroe_*.csv"))[0]).read()
    txt = open(glob.glob(os.path.join(res, "janeroe_*.txt"))[0]).read()
    report = open(glob.glob(os.path.join(res, "janeroe_report_*.html"))[0]).read()
    graph = open(os.path.join(res, "janeroe_graph.html")).read()
    for doc in (csv_text, txt, report, graph):
        assert "Globex" in doc and "Adobe" in doc and ONION_A[:16] in doc


@pytest.mark.asyncio
async def test_without_the_flags_no_third_party_is_queried(site, api, ahmia, monkeypatch, tmp_path):
    from test_breachdb import Handler as BreachHandler
    from test_robin import Handler as AhmiaHandler
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(helix, "PLATFORMS", {"Exampleweb": {
        "url": site + "/u/{username}", "method": "status_code", "found": [200],
        "category": "social", "color": "#fff"}})

    async def no_email_scan(email):
        return []
    monkeypatch.setattr(helix, "check_email", no_email_scan)
    monkeypatch.setenv("HIBP_API_KEY", "good-key")

    await helix.run(_args(tmp_path, breach=False, darkweb=False))
    assert BreachHandler.hibp_keys == [] and AhmiaHandler.queries == []
