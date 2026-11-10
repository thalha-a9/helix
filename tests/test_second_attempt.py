"""
Second attempt: a site that gave no clear answer is asked again.

Measured on 10 Nov 2026, full database, made-up name: 1,531 of 12,111 sites
gave no clear answer. 238 of them were fediverse servers whose hosting
company answered HTTP 403 or 429 for the lookup API while WebFinger, on the
same server, still answered. A second attempt must never cost accuracy: a
result is replaced only by a clear answer, and a hit found on the second
attempt goes through the whole control probe, read by the rule that found it.
"""

import http.server
import socket
import threading

import aiohttp
import pytest

import osint.checker as ck
from osint import evidence
from osint.adapters import fediverse_adapter as fa
from osint.checker import (CERT_ERROR, CONTROL_ERROR, DNS_ERROR, DNS_TEMPORARY, RECHECK_ERROR,
                           check_username, unanswered_kind)
from osint.platform_schema import fallback_defs, problems

STATE = {"once": 0, "midway": 0, "stuck": 0, "hits": []}


def _webfinger(path):
    # /wf/<site>?resource=acct:NAME@host
    name = path.split("acct:", 1)[1].split("@", 1)[0]
    if name.lower() == "janeroe":
        return 200, b'{"subject":"acct:janeroe@example.social","links":[]}'
    return 404, b""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        STATE["hits"].append(path)
        headers = {}
        if path.startswith("/wf/"):
            status, body = _webfinger(path)
        elif path.startswith("/echo/"):
            # A broken fallback: names whoever is asked for.
            name = path.split("acct:", 1)[1].split("@", 1)[0].encode()
            status, body = 200, b'{"subject":"acct:' + name + b'@example.social"}'
        elif path.startswith("/gone/"):
            status, body = 404, b""                       # says nobody exists
        elif path.startswith("/limited/"):
            status, body = 403, b'{"error":"An unusual number of requests from your network"}'
        elif path.startswith("/once/"):
            # Rate-limited on the first request only.
            STATE["once"] += 1
            if STATE["once"] == 1:
                status, body, headers = 429, b"slow down", {"Retry-After": "0"}
            elif path.endswith("/janeroe"):
                status, body = 200, b"<html>janeroe - 42 posts</html>"
            else:
                status, body = 404, b"<html>Not Found</html>"
        elif path.startswith("/stuck/"):
            # 429, then a server error: never a clear answer.
            STATE["stuck"] += 1
            status, body = (429, b"slow down") if STATE["stuck"] == 1 else (500, b"oops")
        elif path.startswith("/midway/"):
            # Answers the sweep, then the hoster's limit kicks in.
            STATE["midway"] += 1
            if STATE["midway"] == 1 and path.endswith("=janeroe"):
                status, body = 200, b'{"id":"1","username":"janeroe"}'
            else:
                status, body = 403, b'{"error":"logged-out access is limited for now"}'
        else:
            status, body = 404, b"<html>Not Found</html>"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


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
    STATE.update(once=0, midway=0, stuck=0, hits=[])


def server_like(base, primary, fallback="wf"):
    """A Mastodon-style definition: lookup API first, WebFinger as fallback."""
    return {"url": f"{base}/@{{username}}", "category": "social", "color": "#6364ff",
            "source": "fediverse",
            "check_url": f"{base}/{primary}/lookup?acct={{username}}",
            "method": "text_present", "found_text": '"username":"{username}"',
            "fallbacks": [{"check_url": f"{base}/{fallback}/x?resource=acct:{{username}}@example.social",
                           "method": "text_present", "found_text": "acct:{username}@"}]}


def page(base, kind):
    return {"url": f"{base}/{kind}/{{username}}", "method": "status_code", "found": [200],
            "category": "social", "color": "#fff"}


async def scan(username, platforms, **kw):
    return {r["platform"]: r for r in await check_username(username, platforms=platforms, **kw)}


# The fallback rule

@pytest.mark.asyncio
async def test_a_blocked_api_is_answered_by_the_fallback_rule(base):
    r = (await scan("janeroe", {"S": server_like(base, "limited")}))["S"]
    assert r["found"] is True and r["recovered"] == "fallback"
    # The profile address shown is still the profile page, not the lookup.
    assert r["url"] == f"{base}/@janeroe"
    # The hit and every made-up name were read by the fallback rule.
    asked = [p for p in STATE["hits"] if p.startswith("/wf/")]
    names = {p.split("acct:", 1)[1].split("@", 1)[0] for p in asked}
    assert "janeroe" in names and len(names) >= 4
    assert sum("acct:janeroe@" in p for p in asked) == 3


@pytest.mark.asyncio
async def test_a_made_up_name_gets_a_clear_no_from_the_fallback(base):
    r = (await scan("zq8rk2vx0bnm", {"S": server_like(base, "limited")}))["S"]
    assert r["found"] is False and r["error"] is None and r["status_code"] == 404
    assert r["recovered"] == "fallback"
    assert evidence.summarise([r])["answered"] == 1


@pytest.mark.asyncio
async def test_without_the_second_attempt_the_site_stays_unanswered(base):
    r = (await scan("janeroe", {"S": server_like(base, "limited")}, recover=False))["S"]
    assert r["found"] is False and r["status_code"] == 403 and "recovered" not in r
    assert evidence.summarise([r])["answered"] == 0


@pytest.mark.asyncio
async def test_a_fallback_that_finds_everyone_is_discarded_by_the_control_probe(base):
    r = (await scan("janeroe", {"S": server_like(base, "limited", fallback="echo")}))["S"]
    assert r["found"] is False and r["error"] == CONTROL_ERROR and r["control_failed"]


# The same request again

@pytest.mark.asyncio
async def test_a_rate_limited_site_is_asked_again(base):
    r = (await scan("zq8rk2vx0bnm", {"Once": page(base, "once")}))["Once"]
    assert r["found"] is False and r["status_code"] == 404 and r["recovered"] == "retry"
    assert "_retry_after" not in r


@pytest.mark.asyncio
async def test_only_a_clear_answer_replaces_the_first_result(base):
    r = (await scan("zq8rk2vx0bnm", {"Stuck": page(base, "stuck")}))["Stuck"]
    assert r["status_code"] == 429 and "recovered" not in r
    assert evidence.summarise([r])["unanswered"] == 1


@pytest.mark.asyncio
async def test_the_site_is_told_how_many_are_asked_again(base):
    told = []
    await scan("zq8rk2vx0bnm", {"Once": page(base, "once"), "Fine": page(base, "fine")},
               recover_cb=told.append)
    assert told == [1]


@pytest.mark.parametrize("result,kind", [
    ({"found": True}, ""),
    ({"found": False, "status_code": 404}, ""),
    ({"found": False, "error": "timeout"}, "timeout"),
    ({"found": False, "error": DNS_ERROR}, "dns"),
    ({"found": False, "error": DNS_TEMPORARY}, "connect"),
    ({"found": False, "error": CERT_ERROR}, "certificate"),
    ({"found": False, "error": "connection_error"}, "connect"),
    ({"found": False, "error": "Server disconnected"}, "connect"),
    ({"found": False, "error": "waf_blocked: bot-check page detected"}, "botcheck"),
    ({"found": False, "status_code": 429}, "rate"),
    ({"found": False, "status_code": 403}, "refused"),
    ({"found": False, "status_code": 503}, "server"),
    ({"found": False, "error": "unexpected: boom"}, "other"),
])
def test_what_stood_in_the_way(result, kind):
    assert unanswered_kind(result) == kind


@pytest.mark.asyncio
async def test_dead_hosts_bad_certificates_and_timeouts_are_not_asked_again(monkeypatch):
    calls = []
    errors = {"Dns": DNS_ERROR, "Cert": CERT_ERROR, "Slow": "timeout",
              "Tls": "requires curl_cffi (pip install curl-cffi)",
              "Soft": "soft404_body: page body indicates user not found"}

    async def fake_check(session, name, plat, username, sem, fast=False):
        calls.append(name)
        return {"platform": name, "found": False, "error": errors[name]}

    monkeypatch.setattr(ck, "check_platform", fake_check)
    told = []
    await check_username("janeroe", platforms={k: {} for k in errors}, control=False,
                         recover_cb=told.append)
    assert sorted(calls) == sorted(errors) and told == []


def test_connection_failures_say_what_failed():
    class Dns(Exception):
        os_error = socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    class Busy(Exception):
        os_error = socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

    class Reset(Exception):
        os_error = ConnectionResetError(104, "Connection reset by peer")

    assert ck._connect_error(Dns()) == DNS_ERROR
    assert ck._connect_error(Busy()) == DNS_TEMPORARY
    assert ck._connect_error(Reset()) == "connection_error"
    assert issubclass(aiohttp.ClientConnectorCertificateError, aiohttp.ClientConnectorError)


@pytest.mark.parametrize("error,reason", [
    (DNS_ERROR, "host name does not resolve"),
    (CERT_ERROR, "invalid HTTPS certificate"),
    (DNS_TEMPORARY, "connection error"),
    ("connection_error", "connection error"),
])
def test_the_evidence_names_dead_hosts_and_bad_certificates(error, reason):
    assert evidence.reason_of(error) == reason


@pytest.mark.parametrize("header,seconds", [
    ({"Retry-After": "7"}, 7.0), ({"Retry-After": "0"}, 0.0), ({}, None),
    ({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, None), ({"Retry-After": "-3"}, 0.0),
])
def test_retry_after_is_read_in_seconds(header, seconds):
    assert ck._retry_after(header) == seconds


# The control probe, blocked part of the way

@pytest.mark.asyncio
async def test_a_probe_blocked_midway_is_run_again_by_the_fallback_rule(base):
    r = (await scan("janeroe", {"S": server_like(base, "midway")}))["S"]
    assert r["found"] is True and r["verified_by"] == "fallback"
    asked = [p for p in STATE["hits"] if p.startswith("/wf/")]
    assert sum("acct:janeroe@" in p for p in asked) == 2      # the hit, twice more
    assert len({p for p in asked if "acct:janeroe@" not in p}) >= 3


@pytest.mark.asyncio
async def test_a_fallback_that_says_no_such_user_drops_the_hit(base):
    r = (await scan("janeroe", {"S": server_like(base, "midway", fallback="gone")}))["S"]
    assert r["found"] is False and r["error"] == RECHECK_ERROR


@pytest.mark.asyncio
async def test_a_broken_fallback_cannot_confirm_a_blocked_probe(base):
    r = (await scan("janeroe", {"S": server_like(base, "midway", fallback="echo")}))["S"]
    assert r["found"] is False and r["error"] == CONTROL_ERROR


# Definitions

def test_a_fallback_takes_the_profile_address_and_labels_only():
    pdef = server_like("https://example.social", "api")
    (fb,) = fallback_defs(pdef)
    assert fb["url"] == pdef["url"] and fb["source"] == "fediverse"
    assert fb["found_text"] == "acct:{username}@" and "webfinger" not in pdef["check_url"]
    assert "fallbacks" not in fb
    assert fallback_defs({"url": "x"}) == [] and fallback_defs(None) == []


def test_fallbacks_are_validated_like_any_definition():
    good = server_like("https://example.social", "api")
    assert problems(good) == []
    empty = {**good, "fallbacks": [{"check_url": good["check_url"], "method": "text_present"}]}
    assert any("fallback 1" in p and "found_text" in p for p in problems(empty))
    assert problems({**good, "fallbacks": "webfinger"}) == ["fallbacks is not a list of definitions"]
    nested = {**good, "fallbacks": [{**good["fallbacks"][0], "fallbacks": []}]}
    assert any("fallbacks of its own" in p for p in problems(nested))


@pytest.mark.parametrize("software", ["mastodon", "misskey", "lemmy", "peertube"])
def test_every_fediverse_server_can_be_asked_by_webfinger(software):
    pdef = fa.platform_for("example.social", software)
    (fb,) = fallback_defs(pdef)
    assert problems(pdef) == []
    assert fb["check_url"] == ("https://example.social/.well-known/webfinger"
                               "?resource=acct:{username}@example.social")
    assert fb["url"] == pdef["url"]


@pytest.mark.asyncio
@pytest.mark.parametrize("software,reply,found", [
    # Replies as lemmy.ml and framatube.org gave them on 10 Nov 2026.
    ("lemmy", '{"subject":"acct:janeroe@x","links":[{"rel":"self","href":"https://x/u/janeroe",'
              '"properties":{"https://www.w3.org/ns/activitystreams#type":"Person"}}]}', True),
    ("lemmy", '{"subject":"acct:janeroe@x","links":[{"rel":"self","href":"https://x/c/janeroe",'
              '"properties":{"https://www.w3.org/ns/activitystreams#type":"Group"}}]}', False),
    ("peertube", '{"subject":"acct:janeroe@x","aliases":["https://x/accounts/janeroe"]}', True),
    ("peertube", '{"subject":"acct:janeroe@x","aliases":["https://x/video-channels/janeroe"]}', False),
    ("mastodon", '{"subject":"acct:JaneRoe@x","aliases":["https://x/@JaneRoe"]}', True),
    ("misskey", '{"subject":"acct:janeroe@x","links":[]}', True),
    ("mastodon", '{"subject":"acct:janeroe99@x"}', False),
])
async def test_webfinger_reads_a_person_not_a_community_or_channel(software, reply, found):
    (fb,) = fallback_defs(fa.platform_for("x", software))
    result = {"platform": "x", "url": "", "found": False, "error": None}
    await ck._apply(result, fb, "janeroe", 200, reply, fb["check_url"])
    assert result["found"] is found


# Counting

def test_the_evidence_counts_second_attempts_by_how():
    results = [{"platform": "A", "found": False, "status_code": 404, "recovered": "fallback"},
               {"platform": "B", "found": True, "recovered": "fallback"},
               {"platform": "C", "found": False, "status_code": 404, "recovered": "retry"},
               {"platform": "D", "found": False, "status_code": 404}]
    s = evidence.summarise(results)
    assert s["second_attempt"] == {"fallback": 2, "retry": 1}
    assert s["answered"] == 4
    assert "second_attempt" in evidence.COUNTING_RULES
