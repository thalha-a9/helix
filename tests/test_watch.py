"""
--watch: a username's accounts over time, with a hash-chained history.

The rule behind every Helix count holds here too: a site that did not answer
is not a site without an account. An account is called "removed" only when
its site clearly says "no such user", and "new" only when the site clearly
said so last time.
"""

import argparse
import http.server
import json
import os
import socket
import threading

import pytest

from helix_osint import cli as helix
import helix_osint.checker as ck
from helix_osint import watch

T1, T2, T3 = "2026-11-10T04:00:00+00:00", "2026-11-11T04:00:00+00:00", "2026-11-12T04:00:00+00:00"


def site(name):
    return {"url": f"https://{name}.example/{{username}}", "method": "status_code"}


SITES = {n: site(n.lower()) for n in ("Alpha", "Beta", "Gamma", "Delta", "Echo")}


def res(platform, found=False, error=None, status=404, **facts):
    return {"platform": platform, "url": f"https://{platform.lower()}.example/janeroe", "found": found,
            "error": error, "status_code": 200 if found else status, **facts}


def snap(results, when, sites=SITES):
    return watch.snapshot("janeroe", results, sites, when)


# Differences

def test_new_removed_and_changed_need_clear_answers_both_times():
    before = snap([res("Alpha", True, og_title="Jane Roe"), res("Beta", True), res("Gamma"),
                   res("Delta", error="timeout"), res("Echo", True)], T1)
    after = snap([res("Alpha", True, og_title="Jane R."), res("Beta"), res("Gamma", True),
                  res("Delta", True), res("Echo", status=429)], T2)
    d = watch.diff(before, after)
    assert [i["platform"] for i in d["new"]] == ["Gamma"]                 # clear "no" before, found now
    assert [i["platform"] for i in d["removed"]] == ["Beta"]              # found before, clear "no" now
    assert d["first_seen"] == [{"platform": "Delta", "url": "https://delta.example/janeroe",
                                "why": "the site gave no clear answer last time"}]
    assert d["not_checked"] == [{"platform": "Echo", "url": "https://echo.example/janeroe",
                                 "why": "the site gave no clear answer this time"}]
    assert d["changed"] == [{"platform": "Alpha", "url": "https://alpha.example/janeroe",
                             "changes": ["name on the profile: 'Jane Roe' is now 'Jane R.'"]}]


def test_a_site_that_joined_or_left_the_list_is_never_new_or_removed():
    small = {k: SITES[k] for k in ("Alpha", "Beta")}
    before = snap([res("Alpha", True), res("Beta", True)], T1, small)
    wider = {"Alpha": SITES["Alpha"], "Gamma": SITES["Gamma"]}
    after = snap([res("Alpha", True), res("Gamma", True)], T2, wider)
    d = watch.diff(before, after, prev_sites=set(before["_site_keys"]), now_sites=set(after["_site_keys"]))
    assert d["new"] == [] and d["removed"] == []
    assert d["first_seen"][0]["why"] == "the site was not scanned last time"
    assert d["not_checked"][0]["why"] == "the site was not scanned this time"
    # Without the earlier list on file, a different list means "cannot say".
    assert watch.diff(before, after)["new"] == []


def test_a_fact_only_one_snapshot_holds_is_not_a_change():
    before = snap([res("Alpha", True, og_title="Jane Roe", phash="abcd")], T1)
    after = snap([res("Alpha", True, og_title="Jane Roe")], T2)                  # no --phash this time
    assert watch.diff(before, after)["changed"] == []
    later = snap([res("Alpha", True, og_title="Jane Roe", phash="ffff",
                      bio_links={"github": "janeroe", "website": "https://jane.example"},
                      location_hints=["Berlin"])], T3)
    assert watch.diff(before, later)["changed"][0]["changes"] == ["profile picture: 'abcd' is now 'ffff'"]
    links = watch.diff(snap([res("Alpha", True, bio_links={"github": "janeroe"})], T1), later)
    assert links["changed"][0]["changes"] == ["links it lists: added website: https://jane.example"]


def test_unconfirmed_and_discarded_hits_count_as_not_checked():
    before = snap([res("Alpha", True), res("Beta", True)], T1)
    after = snap([res("Alpha", error="unconfirmed: a made-up name the same length as this one was also found"),
                  res("Beta", error="unverifiable: no clear 'not found' for a random username")], T2)
    d = watch.diff(before, after)
    assert d["removed"] == [] and len(d["not_checked"]) == 2


# The chain

def test_snapshots_are_chained_and_any_edit_shows(tmp_path):
    out = str(tmp_path)
    first, prev, changes, path = watch.record(out, "janeroe", snap([res("Alpha", True)], T1))
    assert prev is None and changes is None and first["prev"] == ""
    second, prev, changes, _ = watch.record(out, "janeroe", snap([res("Alpha", True), res("Beta", True)], T2))
    assert second["prev"] == first["hash"] and prev["hash"] == first["hash"]
    assert [i["platform"] for i in changes["first_seen"]] == ["Beta"]      # Beta was not on the first list
    history = watch.load_history(path)
    assert len(history) == 2 and watch.verify_history(history) == []
    assert "_site_keys" not in history[0] and os.path.exists(watch._sites_file(os.path.dirname(path), first["sites_sha256"]))

    edited = json.loads(json.dumps(history))
    edited[0]["accounts"] = {}
    assert watch.verify_history(edited) == [f"snapshot 1 ({T1}) was changed after it was written"]
    assert "does not follow the one before it" in watch.verify_history(history[1:])[0]
    assert watch.verify_history(list(reversed(history))) != []
    assert watch.verify_history([{"schema": "other"}]) == ["snapshot 1 is not a Helix watch snapshot"]


def test_a_tampered_history_is_not_added_to(tmp_path):
    out = str(tmp_path)
    _, _, _, path = watch.record(out, "janeroe", snap([res("Alpha", True)], T1))
    line = json.loads(open(path).read())
    line["accounts"] = {}
    open(path, "w").write(json.dumps(line) + "\n")
    with pytest.raises(ValueError, match="was changed after it was written"):
        watch.record(out, "janeroe", snap([res("Alpha", True)], T2))
    assert len(watch.load_history(path)) == 1


def test_a_history_belongs_to_one_username(tmp_path):
    watch.record(str(tmp_path), "janeroe", snap([res("Alpha", True)], T1))
    other = watch.snapshot("someoneelse", [res("Alpha", True)], SITES, T2)
    with pytest.raises(ValueError, match="this history is for janeroe"):
        watch.record(str(tmp_path), "janeroe", other)


def test_the_report_reads_plainly(tmp_path):
    out = str(tmp_path)
    a = snap([res("Alpha", True), res("Beta")], T1)
    first, prev, changes, _ = watch.record(out, "janeroe", a)
    assert watch.summary_lines(first, prev, changes, 1) == [
        "First snapshot: 1 account(s) on record. Run the same command again later to see what changed."]
    second, prev, changes, _ = watch.record(out, "janeroe", snap([res("Alpha", True), res("Beta")], T2))
    assert watch.summary_lines(second, prev, changes, 2) == [
        f"Snapshot 2, compared with {T1}:", "No change: the same 1 account(s)."]
    third, prev, changes, _ = watch.record(out, "janeroe", snap([res("Alpha"), res("Beta", True)], T3))
    assert watch.summary_lines(third, prev, changes, 3) == [
        f"Snapshot 3, compared with {T2}:",
        "[new] Beta  https://beta.example/janeroe",
        "[removed] Alpha  https://alpha.example/janeroe"]


def test_verify_watch_command(tmp_path, capsys):
    out = str(tmp_path)
    _, _, _, path = watch.record(out, "janeroe", snap([res("Alpha", True)], T1))
    watch.record(out, "janeroe", snap([res("Alpha", True)], T2))
    assert watch.main([os.path.dirname(path)]) == 0
    assert "OK: every snapshot is intact and follows the one before it" in capsys.readouterr().out
    lines = open(path).read().splitlines()
    open(path, "w").write(lines[1] + "\n")                  # the first snapshot was deleted
    assert watch.main([path]) == 1
    assert "a snapshot was removed, added or reordered" in capsys.readouterr().out
    assert watch.main([str(tmp_path / "nothing")]) == 2


# A real scan, twice

class Handler(http.server.BaseHTTPRequestHandler):
    present = {"/a/janeroe"}

    def do_GET(self):
        ok = self.path in Handler.present
        body = (b"<html>janeroe - 42 posts</html>" if ok else b"<html>Not Found</html>")
        self.send_response(200 if ok else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def two_sites(monkeypatch, tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    monkeypatch.setattr(helix, "PLATFORMS", {
        k: {"url": f"{base}/{k.lower()}/{{username}}", "method": "status_code", "found": [200],
            "category": "social", "color": "#fff"} for k in ("A", "B")})
    Handler.present = {"/a/janeroe"}
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
                proxy=None, tor=False, watch=True)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.asyncio
async def test_two_watch_scans_report_what_changed(two_sites, capsys):
    await helix.run(_args())
    out = capsys.readouterr().out
    assert "First snapshot: 1 account(s) on record." in out
    Handler.present = {"/b/janeroe"}
    await helix.run(_args())
    out = capsys.readouterr().out
    assert "[new] B " in out and "[removed] A " in out and "Snapshot 2, compared with" in out
    folder = os.path.join(two_sites, "results", "janeroe", "janeroe_watch")
    assert watch.main([folder]) == 0
    reports = sorted(p for p in os.listdir(os.path.dirname(folder)) if p.startswith("janeroe_2"))
    intel = json.load(open(os.path.join(os.path.dirname(folder), reports[-1])))["intel"]["watch"]
    assert intel["snapshots"] == 2 and [i["platform"] for i in intel["changes"]["new"]] == ["B"]


@pytest.mark.asyncio
async def test_without_the_flag_no_history_is_kept(two_sites):
    await helix.run(_args(watch=False))
    assert not os.path.exists(os.path.join(two_sites, "results", "janeroe", "janeroe_watch"))
