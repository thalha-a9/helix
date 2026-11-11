"""
The daily site check: every site is asked for a made-up name and, where a
database lists an account that exists, for that account. Sites that are dead
or broken three checks in a row are switched off, scans leave them out and
say so, and the first working check switches them back on.
"""

import argparse
import glob
import http.server
import json
import os
import socket
import threading

import pytest

from helix_osint import cli as helix
import helix_osint.checker as ck
from helix_osint import evidence, health
from helix_osint.checker import CERT_ERROR, CONTROL_ERROR, CONTROL_INCONCLUSIVE, DNS_ERROR
from helix_osint.platform_schema import profile_key


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        name = path.rsplit("/", 1)[-1]
        if path.startswith("/good/"):
            ok = name in ("alice", "janeroe")
            status, body = (200, f"<html>{name} - 42 posts</html>") if ok else (404, "<html>Not Found</html>")
        elif path.startswith("/any/"):
            status, body = 200, f"<html>Profile of {name}</html>"       # finds everyone
        elif path.startswith("/wall/"):
            status, body = 403, "<html>Forbidden</html>"
        elif path.startswith("/down/"):
            status, body = 503, "<html>Service Unavailable</html>"
        elif path == "/off.json":
            status, body = 200, json.dumps(Handler.off_list)
        elif path == "/bad.json":
            status, body = 200, '{"schema":"something else","sites":{}}'
        else:
            status, body = 404, "<html>Not Found</html>"
        Handler.hits.append(path)
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


Handler.hits = []
Handler.off_list = {}


@pytest.fixture(scope="module")
def base():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    monkeypatch.setattr(ck, "RECOVERY_WAIT", {})
    Handler.hits.clear()


def site(base, kind, **extra):
    return {"url": f"{base}/{kind}/{{username}}", "method": "status_code", "found": [200],
            "category": "social", "color": "#fff", "source": "maigret", **extra}


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# One check

@pytest.mark.parametrize("result,state,why", [
    ({"found": False, "status_code": 404}, "answers", ""),
    ({"found": True}, "broken", "reported an account for a made-up name"),
    ({"found": False, "error": CONTROL_ERROR}, "broken", "finds made-up names"),
    ({"found": False, "error": CONTROL_INCONCLUSIVE}, "broken",
     "answers a made-up name differently each time"),
    ({"found": False, "error": DNS_ERROR}, "dead", "host name does not resolve"),
    ({"found": False, "error": CERT_ERROR}, "dead", "invalid HTTPS certificate"),
    ({"found": False, "error": "connection_error"}, "dead", "connection failed"),
    ({"found": False, "error": "timeout"}, "dead", "no reply in time"),
    ({"found": False, "status_code": 502}, "dead", "server error (HTTP 502)"),
    ({"found": False, "error": "waf_blocked: bot-check page detected"}, "blocked", "bot-check page"),
    ({"found": False, "status_code": 429}, "blocked", "rate limit (HTTP 429)"),
    ({"found": False, "status_code": 403}, "blocked", "refused (HTTP 403)"),
    ({"found": False, "error": "502, message='Bad Gateway', url='http://user:pw@127.0.0.1:8080'"},
     "unknown", "502, message='Bad Gateway', url='http://***@127.0.0.1:8080'"),
    ({"found": False, "error": "requires curl_cffi (pip install curl-cffi)"},
     "unknown", "requires curl_cffi (pip install curl-cffi)"),
])
def test_each_answer_to_a_made_up_name_has_a_state(result, state, why):
    assert health.classify(result) == (state, why)


@pytest.mark.asyncio
async def test_a_check_proves_sites_with_a_listed_account(base):
    dead = f"http://127.0.0.1:{_free_port()}"
    sites = {
        "Proven": site(base, "good", known="alice"),
        "NoAccountListed": site(base, "good"),
        "AccountGone": site(base, "good", known="deleted-long-ago"),
        "FindsEveryone": site(base, "any", known="alice"),
        "Refuses": site(base, "wall", known="alice"),
        "Down": site(base, "down"),
        "Closed": site(dead, "x"),
    }
    # Each site its own address, as in a real database.
    for i, pdef in enumerate(sites.values()):
        pdef["url"] = pdef["url"].replace("/{username}", f"/s{i}/{{username}}")
    seen = await health.check(sites)
    got = {o["name"]: (o["state"], o["why"]) for o in seen.values()}
    assert got == {
        "Proven": ("proven", ""),
        "NoAccountListed": ("answers", ""),
        "AccountGone": ("answers", "the listed test account was not found"),
        "FindsEveryone": ("broken", "finds made-up names"),
        "Refuses": ("blocked", "refused (HTTP 403)"),
        "Down": ("dead", "server error (HTTP 503)"),
        "Closed": ("dead", "connection failed"),
    }
    assert set(seen) == {profile_key(p["url"]) for p in sites.values()}
    # The listed account is only looked for where the made-up name was refused.
    asked_for_alice = [h for h in Handler.hits if h.endswith("/alice")]
    assert len(asked_for_alice) == 1 and asked_for_alice[0].startswith("/good/")


# The record

def obs(state, why="", name="Site", source="maigret"):
    return {"name": name, "source": source, "state": state, "why": why}


def days(n):
    return f"2026-11-{10 + n:02d}T04:00:00+00:00"


def test_three_failed_checks_in_a_row_switch_a_site_off():
    state = health.new_state()
    for day in range(2):
        state = health.update(state, {"a.example/{username}": obs("dead", "host name does not resolve")}, days(day))
        assert state["sites"]["a.example/{username}"]["off"] is False
    state = health.update(state, {"a.example/{username}": obs("dead", "host name does not resolve")}, days(2))
    entry = state["sites"]["a.example/{username}"]
    assert entry["fails"] == 3 and entry["off"] is True and entry["since"] == days(0)
    assert health.switched_off(state)["sites"] == {
        "a.example/{username}": {"name": "Site", "why": "host name does not resolve", "since": days(0)}}
    assert state["runs"][-1]["off"] == 1 and state["runs"][-1]["dead"] == 1


def test_the_first_working_check_switches_it_back_on():
    state = health.new_state()
    for day in range(3):
        state = health.update(state, {"k": obs("broken", "finds made-up names")}, days(day))
    assert state["sites"]["k"]["off"] is True
    state = health.update(state, {"k": obs("proven")}, days(3))
    assert state["sites"]["k"] == {"fails": 0, "since": days(3), "last_ok": days(3), "name": "Site",
                                   "source": "maigret", "state": "proven", "why": "", "off": False}
    assert health.switched_off(state)["sites"] == {}


def test_checks_on_the_same_day_count_once():
    state = health.new_state()
    for hour in (4, 5, 6, 7):
        state = health.update(state, {"k": obs("dead", "no reply in time")}, f"2026-11-10T{hour:02d}:00:00+00:00")
    assert state["sites"]["k"]["fails"] == 1 and not state["sites"]["k"]["off"]
    assert [r["counted"] for r in state["runs"]] == [True, False, False, False]
    # A closer gap can be asked for, and is written into each run.
    state = health.new_state()
    for hour in (4, 6, 8):
        state = health.update(state, {"k": obs("dead", "no reply in time")},
                              f"2026-11-10T{hour:02d}:00:00+00:00", min_gap_hours=2)
    assert state["sites"]["k"]["off"] is True


def test_a_blocked_site_is_never_switched_off_and_keeps_its_count():
    state = health.new_state()
    for day in range(6):
        state = health.update(state, {"k": obs("blocked", "bot-check page")}, days(day))
    assert state["sites"]["k"]["fails"] == 0 and state["sites"]["k"]["off"] is False
    # Two failures, a blocked day, then a third failure: still three in a row
    # that the site was seen failing, with no working check between.
    state = health.new_state()
    for day, s in enumerate(["dead", "dead", "blocked", "dead"]):
        state = health.update(state, {"k": obs(s, "x")}, days(day))
        assert state["sites"]["k"]["off"] is (day == 3)


def test_sites_that_left_the_database_leave_the_record():
    state = health.update(health.new_state(), {"a": obs("proven"), "b": obs("dead", "x")}, days(0))
    state = health.update(state, {"a": obs("proven")}, days(1))
    assert list(state["sites"]) == ["a"] and state["runs"][-1]["sites"] == 1


def test_the_record_keeps_a_bounded_history():
    state = health.new_state()
    for i in range(health.KEEP_RUNS + 5):
        state = health.update(state, {"a": obs("proven")}, f"2027-01-01T00:00:{i % 60:02d}+00:00")
    assert len(state["runs"]) == health.KEEP_RUNS


def test_the_record_round_trips(tmp_path):
    state = health.update(health.new_state(), {"a": obs("proven")}, days(0), seconds=12.34, where="lab")
    path = str(tmp_path / "status" / "state.json")
    health.save_state(state, path)
    assert health.load_state(path) == state
    assert state["runs"][0]["seconds"] == 12.3 and state["runs"][0]["where"] == "lab"
    assert health.load_state(str(tmp_path / "missing.json")) == health.new_state()
    (tmp_path / "other.json").write_text('{"schema": "x"}')
    with pytest.raises(ValueError):
        health.load_state(str(tmp_path / "other.json"))


# What a scan does with the list

def off_list(*keys, updated="2026-11-12T04:00:00+00:00"):
    return {"schema": health.OFF_SCHEMA, "updated_utc": updated,
            "sites": {k: {"name": "Gone", "why": "host name does not resolve", "since": days(0)}
                      for k in keys}}


def test_switched_off_sites_are_matched_by_profile_address():
    pm = {"Gone": {"url": "https://www.Gone.example/u/{username}/"},
          "Here": {"url": "https://here.example/{username}"}}
    kept, left_out = health.apply_switched_off(pm, off_list("gone.example/u/{username}"))
    assert list(kept) == ["Here"]
    assert left_out == [{"platform": "Gone", "url": pm["Gone"]["url"],
                         "why": "host name does not resolve", "since": days(0)}]
    assert health.apply_switched_off(pm, {"sites": {}}) == (pm, [])
    assert health.apply_switched_off(pm, None) == (pm, [])


def test_the_shipped_list_is_a_valid_list():
    data = json.loads(health.SHIPPED_OFF.read_text())
    assert health._valid_off(data)
    assert all(set(v) == {"name", "why", "since"} for v in data["sites"].values())


def test_a_newer_download_wins_over_the_shipped_list(monkeypatch, tmp_path):
    shipped = tmp_path / "shipped.json"
    shipped.write_text(json.dumps(off_list("a", updated="2026-11-10T00:00:00+00:00")))
    monkeypatch.setattr(health, "SHIPPED_OFF", shipped)
    assert list(health.load_switched_off()["sites"]) == ["a"]
    health._CACHE_OFF.write_text(json.dumps(off_list("b", updated="2026-11-12T00:00:00+00:00")))
    assert list(health.load_switched_off()["sites"]) == ["b"]
    health._CACHE_OFF.write_text(json.dumps(off_list("c", updated="2026-11-01T00:00:00+00:00")))
    assert list(health.load_switched_off()["sites"]) == ["a"]
    health._CACHE_OFF.write_text("not json")
    assert list(health.load_switched_off()["sites"]) == ["a"]
    health._CACHE_OFF.write_text(json.dumps({"schema": health.OFF_SCHEMA, "sites": ["x"]}))
    assert list(health.load_switched_off()["sites"]) == ["a"]


@pytest.mark.asyncio
async def test_todays_list_is_fetched_once_a_day(base):
    Handler.off_list = off_list("fresh.example/{username}")
    assert await health.refresh_switched_off(url=base + "/off.json") is True
    assert list(health.load_switched_off()["sites"]) == ["fresh.example/{username}"]
    assert await health.refresh_switched_off(url=base + "/off.json") is False
    assert Handler.hits.count("/off.json") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/bad.json", "/missing.json"])
async def test_a_bad_or_missing_list_changes_nothing_and_is_not_asked_for_again(base, path):
    assert await health.refresh_switched_off(url=base + path) is False
    assert health.load_switched_off()["sites"] == json.loads(health.SHIPPED_OFF.read_text())["sites"]
    assert await health.refresh_switched_off(url=base + path) is False
    assert Handler.hits.count(path) == 1


@pytest.mark.asyncio
async def test_an_unreachable_list_is_silent():
    assert await health.refresh_switched_off(url=f"http://127.0.0.1:{_free_port()}/off.json") is False


# The page

def test_the_page_is_one_file_and_cannot_be_broken_by_a_site_name(tmp_path):
    hostile = '</script><script>alert(1)</script><img src=x onerror=alert(2)>'
    state = health.update(health.new_state(),
                          {"evil.example/{username}": obs("dead", "x", name=hostile),
                           "ok.example/{username}": obs("proven", name="Fine")}, days(0))
    page = health.render_page(state)
    assert page.count("</script>") == 2 and "<script>alert" not in page
    assert "<img src=x" not in page
    data = page.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0]
    parsed = json.loads(data)
    assert [s[1] for s in parsed["sites"]] == [hostile, "Fine"]         # failing sites first
    assert "innerHTML" not in page and " src=" not in page.split("<script", 1)[0]
    assert 'href="http' not in page.replace('href="https://github.com/thalha-a9/helix"', "")
    paths = health.write_outputs(state, str(tmp_path / "status"))
    assert open(paths["page"]).read() == page
    assert json.load(open(paths["off"]))["schema"] == health.OFF_SCHEMA


def test_the_command_line_rebuilds_the_page(tmp_path, capsys):
    path = str(tmp_path / "state.json")
    health.save_state(health.update(health.new_state(), {"a": obs("proven")}, days(0)), path)
    assert health.main(["page", "--state", path]) == 0
    assert os.path.exists(tmp_path / "index.html") and os.path.exists(tmp_path / "switched_off.json")


# A scan

def _args(**kw):
    base = dict(username="janeroe", email=None, providers=False, ai=None,
                all_sources=False, wmn=False, sherlock=False, maigret=False,
                maigret_engine=False, maigret_timeout=30, maigret_top=10, wmn_timeout=30,
                sherlock_timeout=30, no_control=False, wayback=False, crt=False, paste=False,
                breach=False, darkweb=False, holehe=False, pivot=False, pivot_depth=1,
                phash=False, permutations=False, location=None, format="json", report=False,
                email_permute=False, output=None, no_browser=True, nsfw=False,
                proxy=None, tor=False, record_attempt=True)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def two_sites(base, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    sites = {"Good": site(base, "good"),
             "Gone": {**site(base, "down"), "url": base + "/down/gone/{username}"}}
    monkeypatch.setattr(helix, "PLATFORMS", sites)
    shipped = tmp_path / "shipped.json"
    shipped.write_text(json.dumps(off_list(profile_key(sites["Gone"]["url"]))))
    monkeypatch.setattr(health, "SHIPPED_OFF", shipped)
    return tmp_path


@pytest.mark.asyncio
async def test_a_scan_leaves_switched_off_sites_out_and_says_so(two_sites, capsys):
    await helix.run(_args())
    out = capsys.readouterr().out
    assert "1 site(s) left out: dead or broken on 3 daily checks in a row (list of 2026-11-12)" in out
    assert "--include-off scans them anyway" in out
    assert not any(h.startswith("/down/") for h in Handler.hits)
    res = os.path.join(two_sites, "results", "janeroe")
    ev = json.load(open(os.path.join(res, "janeroe_evidence.json")))
    assert ev["summary"]["attempted"] == 1 and ev["summary"]["found"] == 1
    assert ev["database"]["sites"] == 1
    assert ev["database"]["switched_off"] == {"count": 1, "list_updated_utc": "2026-11-12T04:00:00+00:00"}
    assert "more sites left out: switched off by the daily site check" in out
    assert evidence.verify(ev, json.load(open(os.path.join(res, "janeroe_sites.json")))) == []
    report = json.load(open(glob.glob(os.path.join(res, "janeroe_2*.json"))[0]))
    left = report["intel"]["sites_left_out"]
    assert left["count"] == 1 and left["sites"][0]["platform"] == "Gone"
    assert left["sites"][0]["why"] == "host name does not resolve"


@pytest.mark.asyncio
async def test_include_off_scans_them_anyway(two_sites, capsys):
    await helix.run(_args(include_off=True))
    out = capsys.readouterr().out
    assert "left out" not in out
    assert any(h.startswith("/down/") for h in Handler.hits)
    ev = json.load(open(os.path.join(two_sites, "results", "janeroe", "janeroe_evidence.json")))
    assert ev["summary"]["attempted"] == 2 and "switched_off" not in ev["database"]


@pytest.mark.asyncio
async def test_a_scan_of_the_built_in_sites_downloads_nothing(two_sites, monkeypatch):
    async def must_not_run(*a, **kw):
        raise AssertionError("the built-in scan fetched the switched-off list")
    monkeypatch.setattr(health, "refresh_switched_off", must_not_run)
    await helix.run(_args())


# The daily job

def test_the_daily_job_runs_only_in_the_public_repository_and_keeps_one_commit():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".github", "workflows", "site-check.yml")
    if not os.path.exists(path):
        pytest.skip("workflow files are not part of the installed package")
    wf = open(path, encoding="utf-8").read()
    assert "if: github.repository == 'thalha-a9/helix'" in wf
    assert 'cron: "17 3 * * *"' in wf and "workflow_dispatch" in wf
    assert "python -m helix_osint.health check --state status/state.json --out status" in wf
    assert "git push -q -f" in wf and " status\n" in wf
    assert health.OFF_URL == "https://raw.githubusercontent.com/thalha-a9/helix/status/switched_off.json"


@pytest.mark.asyncio
async def test_a_fediverse_server_is_proven_with_an_account_it_names_itself(base, monkeypatch):
    from helix_osint.adapters import fediverse_adapter
    asked = []

    async def named_by_the_server(domains, concurrency=60, progress_cb=None):
        asked.extend(domains)
        return {"with.example": "alice"}

    monkeypatch.setattr(fediverse_adapter, "known_accounts", named_by_the_server)
    sites = {"with.example": {**site(base, "good", source="fediverse"), "url": base + "/good/a/{username}"},
             "silent.example": {**site(base, "good", source="fediverse"), "url": base + "/good/b/{username}"},
             "Forum": {**site(base, "good"), "url": base + "/good/c/{username}"}}
    seen = await health.check(sites)
    got = {o["name"]: o["state"] for o in seen.values()}
    assert got == {"with.example": "proven", "silent.example": "answers", "Forum": "answers"}
    assert sorted(asked) == ["silent.example", "with.example"]       # only servers without a listed account
