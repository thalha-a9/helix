"""
--me: a person checks their own username and gets, for each account, the
place to delete it or a request to send.
"""

import argparse
import http.server
import json
import os
import socket
import threading

import pytest

import helix
import osint.checker as ck
from osint import mine

GUIDE_RAW = [
    {"name": "GitHub", "url": "https://github.com/settings/admin", "difficulty": "easy",
     "notes": "Settings, Account, Delete your account", "domains": ["github.com"]},
    {"name": "Tumblr", "url": "https://www.tumblr.com/account/delete", "difficulty": "medium",
     "domains": ["tumblr.com"]},
    {"name": "Script", "url": "javascript:alert(1)", "difficulty": "easy", "domains": ["evil.example"]},
    {"name": "NoDomains", "url": "https://x.example/delete", "difficulty": "easy", "domains": []},
    "not an entry",
]
GUIDE = [e for e in map(mine._trim, GUIDE_RAW) if e]


def acc(platform, url):
    return {"platform": platform, "url": url, "found": True}


def test_only_sound_guide_entries_are_kept():
    assert [e["name"] for e in GUIDE] == ["GitHub", "Tumblr"]            # no script links, no entry without a domain
    assert GUIDE[1]["notes"] == "" and GUIDE[0]["domains"] == ["github.com"]


def test_an_account_gets_its_sites_deletion_page_also_on_a_subdomain():
    found = [acc("GitHub", "https://github.com/janeroe"), acc("Tumblr", "https://janeroe.tumblr.com/"),
             acc("Forum", "https://forum.example/u/janeroe"), acc("Fake", "https://notgithub.com/janeroe")]
    assert mine.attach(found, GUIDE) == 2
    assert found[0]["delete"] == {"url": "https://github.com/settings/admin", "difficulty": "easy",
                                  "notes": "Settings, Account, Delete your account", "source": "JustDeleteMe"}
    assert found[1]["delete"]["difficulty"] == "medium"
    assert "delete" not in found[2] and "delete" not in found[3]
    assert mine.terminal_lines(found) == [
        "[no record] Fake  https://notgithub.com/janeroe",
        "[no record] Forum  https://forum.example/u/janeroe",
        "[easy] GitHub  https://github.com/janeroe",
        "    delete: https://github.com/settings/admin",
        "[medium] Tumblr  https://janeroe.tumblr.com/",
        "    delete: https://www.tumblr.com/account/delete"]


def test_the_erasure_request_names_the_account_and_both_laws():
    text = mine.erasure_request("janeroe", [acc("Forum", "https://forum.example/u/janeroe")])
    assert "Username: janeroe" in text and "Forum: https://forum.example/u/janeroe" in text
    assert "Article 17" in text and "Digital\nPersonal Data Protection Act, 2023" in text and "section 12" in text
    assert "not legal advice" in text


def test_the_page_lists_every_account_and_cannot_be_broken_by_a_site():
    found = [acc("GitHub", "https://github.com/janeroe"),
             acc('<script>alert(1)</script>', 'javascript:alert(2)')]
    mine.attach(found, GUIDE)
    found[0]["delete"]["notes"] = '<img src=x onerror=alert(3)>'
    page = mine.page("janeroe", "", found, answered=9000, unanswered=400, when="2026-11-10")
    assert "2 account(s) found on the 9000 sites that answered" in page
    assert "400 more sites gave no clear answer" in page and "may not be complete" in page
    assert 'href="https://github.com/settings/admin"' in page
    assert "<script>alert" not in page and "<img src=x" not in page and 'href="javascript' not in page
    assert "Erasure request" in page and "only you know whether it is yours" in page
    assert "Leaks" not in page


def test_the_page_says_what_to_do_about_a_leak_and_when_nothing_was_checked():
    leaked = [{"identifier": "j@example.com", "exposed": True,
               "summary": "j@example.com appears in 1 breach (2013)",
               "breaches": [{"name": "Adobe", "date": "2013", "data_classes": ["Passwords"],
                             "sources": ["XposedOrNot"]}], "sources": []}]
    page = mine.page("", "j@example.com", [], 100, 0, breaches=leaked)
    assert "Leaks" in page and "change the password" in page and "No accounts found" in page
    assert "j@example.com appears in 1 breach (2013)" in page and "exposed: Passwords" in page
    clean = mine.page("", "j@example.com", [], 100, 0, breaches=[{"identifier": "j@example.com", "exposed": False}])
    assert "is not in the breach lists that were checked" in clean
    unknown = mine.page("", "j@example.com", [], 100, 0, breaches=[{"identifier": "j@example.com", "exposed": None}])
    assert "could not be checked this time" in unknown


# A real run

class Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path.endswith("/janeroe")
        body = b"<html>janeroe - 42 posts</html>" if ok else b"<html>Not Found</html>"
        self.send_response(200 if ok else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


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
            "category": "social", "color": "#fff"} for k in ("Listed", "Unlisted")})

    async def guide(timeout=25.0):
        return [{"name": "Listed", "url": "https://listed.example/delete", "difficulty": "hard",
                 "notes": "Write to support", "email": "", "domains": ["127.0.0.1"]}]
    monkeypatch.setattr(mine, "load_guide", guide)
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
                proxy=None, tor=False, me=True, record_attempt=True, purpose=mine.PURPOSE)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.asyncio
async def test_a_self_check_writes_the_page_and_seals_its_purpose(site, capsys):
    await helix.run(_args())
    out = capsys.readouterr().out
    assert "Your accounts" in out and "2 found; 2 with a deletion page on record (JustDeleteMe)" in out
    assert "[hard] Listed" in out and "delete: https://listed.example/delete" in out
    res = os.path.join(site, "results", "janeroe")
    page = open(os.path.join(res, "janeroe_my_accounts.html")).read()
    assert "Write to support" in page and "you have to contact the site" in page
    ev = json.load(open(os.path.join(res, "janeroe_evidence.json")))
    assert ev["attempt"]["purpose"] == "self-check: my own accounts"
    assert "Purpose   self-check: my own accounts" in out


@pytest.mark.asyncio
async def test_without_a_guide_every_account_gets_the_erasure_request(site, monkeypatch, capsys):
    async def nothing(timeout=25.0):
        return []
    monkeypatch.setattr(mine, "load_guide", nothing)
    await helix.run(_args())
    out = capsys.readouterr().out
    assert "The deletion guide could not be fetched" in out and "Erasure request for the 2 other(s)" in out
    letter = open(os.path.join(site, "results", "janeroe", "janeroe_erasure_request.txt")).read()
    assert "Listed:" in letter and "Unlisted:" in letter


def test_the_flag_means_all_sources_the_breach_lists_and_a_stated_purpose(monkeypatch):
    seen = {}

    async def fake_run(args):
        seen.update(vars(args))
    monkeypatch.setattr(helix, "run", fake_run)
    monkeypatch.setattr(helix.sys, "argv", ["helix", "--me", "-u", "janeroe", "-e", "j@example.com"])
    helix.main()
    assert seen["all_sources"] and seen["wmn"] and seen["fediverse"] and seen["breach"]
    assert seen["purpose"] == "self-check: my own accounts"
    monkeypatch.setattr(helix.sys, "argv", ["helix", "--me", "-u", "janeroe", "--purpose", "audit"])
    helix.main()
    assert seen["purpose"] == "audit" and seen["breach"] is False
