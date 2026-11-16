"""
The library calls other programs build on: an email scan, the left-out check,
a sealed record of a report, and stopping a scan part way.
"""

import asyncio
import http.server
import json
import socket
import threading
import time

import pytest

import helix_osint
import helix_osint.checker as ck
from helix_osint import api, leftout


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        kind, _, name = self.path.strip("/").partition("/")
        if kind == "slow":
            time.sleep(3)
        if kind == "good" and name == "janeroe":
            status, body = 200, b"<html>janeroe - 42 posts</html>"
        else:
            status, body = 404, b"<html>Not Found</html>"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _plat(base, kind):
    return {"url": f"{base}/{kind}/{{username}}", "method": "status_code", "found": [200],
            "category": "social", "color": "#fff"}


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(ck, "CONTROL_RETRY_DELAY", 0)
    monkeypatch.setattr(ck, "RECOVERY_WAIT", {})


@pytest.fixture
def no_list(monkeypatch):
    """No downloads and an empty left-out list unless a test sets one."""
    async def offline(*a, **k):
        return False
    monkeypatch.setattr(leftout, "refresh", offline)
    monkeypatch.setattr(leftout, "load", lambda: set())


def test_the_public_names_are_stable():
    assert api.SCHEMA == "helix.scan.v1"
    assert api.__version__ == helix_osint.__version__
    for name in ("scan", "scan_sync", "scan_email", "scan_email_sync", "is_left_out",
                 "refresh_left_out", "record_attempt", "verify_evidence", "LeftOut"):
        assert name in api.__all__ and hasattr(api, name)


@pytest.mark.asyncio
async def test_a_username_report_says_what_it_is_and_how_many_made_up_names(base, no_list):
    report = await api.scan("janeroe", platforms={"Good": _plat(base, "good")}, controls=5)
    assert report["target_type"] == "username" and report["username"] == "janeroe"
    assert report["controls"] == 5
    assert [a["platform"] for a in report["accounts"]] == ["Good"]


@pytest.mark.asyncio
async def test_a_sealed_record_of_a_report_checks_out_and_catches_any_change(base, no_list):
    report = await api.scan("janeroe", platforms={"Good": _plat(base, "good"),
                                                  "Empty": _plat(base, "empty")},
                            purpose="my own accounts")
    record, sites = api.record_attempt(report, collector="thalha-a9")
    assert record["schema"] == "helix.record-attempt.v1"
    assert record["attempt"]["username"] == "janeroe" and "target_type" not in record["attempt"]
    assert record["attempt"]["purpose"] == "my own accounts"
    assert record["attempt"]["collector"] == "thalha-a9"
    assert record["attempt"]["controls"] == 3 and record["attempt"]["control_probe"] is True
    assert record["summary"]["attempted"] == 2 and record["summary"]["found"] == 1
    assert record["found"] == [{"platform": "Good", "url": f"{base}/good/janeroe", "source": "builtin"}]
    assert api.verify_evidence(record, sites) == []

    # Saved and read back, it still checks out.
    record2, sites2 = json.loads(json.dumps(record)), json.loads(json.dumps(sites))
    assert api.verify_evidence(record2, sites2) == []

    record2["found"] = []
    assert "fingerprint does not match the file's contents" in api.verify_evidence(record2, sites2)
    sites2["Empty"]["url"] = "https://elsewhere.example/x"
    assert "sites file does not match the database hash in the evidence" in \
        api.verify_evidence(record, sites2)
    with pytest.raises(ValueError):
        api.record_attempt({"schema": "something else"})


EMAIL_RESULTS = [
    {"platform": "Gravatar", "url": "https://en.gravatar.com/abc", "category": "other",
     "found": True, "error": None, "source": "builtin"},
    {"platform": "Other", "url": "https://other.example", "category": "other",
     "found": False, "error": "not checked: HTTP 429", "source": "builtin"},
]


@pytest.mark.asyncio
async def test_an_email_scan_has_the_same_shape_and_rules(monkeypatch, no_list):
    async def fake(email, progress_cb=None):
        assert email == "jane.roe@example.com"
        return [dict(r) for r in EMAIL_RESULTS]
    monkeypatch.setattr(api, "check_email", fake)

    report = await api.scan_email(" jane.roe@example.com ", purpose="agreed with Jane")
    assert report["schema"] == "helix.scan.v1" and report["target_type"] == "email"
    assert report["email"] == "jane.roe@example.com" and "username" not in report
    assert report["purpose"] == "agreed with Jane"
    s = report["summary"]
    assert (s["attempted"], s["found"], s["answered"], s["unanswered"]) == (2, 1, 1, 1)
    assert [a["platform"] for a in report["accounts"]] == ["Gravatar"]
    assert [u["platform"] for u in report["unanswered"]] == ["Other"]
    assert all(r["target_type"] == "email" for r in report["results"])
    json.dumps(report)

    record, sites = api.record_attempt(report)
    assert record["attempt"]["target_type"] == "email"
    assert record["attempt"]["username"] == "jane.roe@example.com"
    assert record["attempt"]["control_probe"] is False and "controls" not in record["attempt"]
    assert api.verify_evidence(record, sites) == []


@pytest.mark.asyncio
async def test_an_email_scan_refuses_bad_and_left_out_addresses(monkeypatch, no_list):
    called = []

    async def fake(email, progress_cb=None):
        called.append(email)
        return []
    monkeypatch.setattr(api, "check_email", fake)

    with pytest.raises(ValueError):
        await api.scan_email("not an address")
    monkeypatch.setattr(leftout, "load", lambda: {leftout.token("Jane.Roe@Example.com")})
    with pytest.raises(api.LeftOut):
        await api.scan_email("jane.roe@example.com")
    assert called == []                                  # nothing was asked of any site


@pytest.mark.asyncio
async def test_holehe_never_runs_password_recovery_modules(monkeypatch, no_list):
    from helix_osint.adapters import holehe_adapter as ha
    seen = {}

    async def fake(email, progress_cb=None, password_recovery=True, include_nsfw=False):
        seen["password_recovery"] = password_recovery
        return [dict(EMAIL_RESULTS[0], source="holehe")]
    monkeypatch.setattr(ha, "HOLEHE_AVAILABLE", True)
    monkeypatch.setattr(ha, "run_holehe", fake)
    report = await api.scan_email("jane.roe@example.com", holehe=True)
    assert seen == {"password_recovery": False}
    assert report["summary"]["found"] == 1


def test_the_left_out_check_covers_usernames_and_addresses(monkeypatch):
    monkeypatch.setattr(leftout, "load", lambda: {leftout.token("janeroe"),
                                                   leftout.token("jane.roe@example.com")})
    assert api.is_left_out("@JaneRoe") and api.is_left_out("JANE.ROE@example.com")
    assert not api.is_left_out("johndoe") and not api.is_left_out("")


@pytest.mark.asyncio
async def test_a_scan_can_be_stopped_part_way(base, no_list):
    task = asyncio.ensure_future(api.scan("janeroe", platforms={
        f"Slow{i}": _plat(base, "slow") for i in range(5)}))
    await asyncio.sleep(0.5)
    t0 = time.time()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.time() - t0 < 2                          # it stops now, not when the sites answer
    await asyncio.sleep(0)
    left = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
    assert left == []                                    # nothing keeps running in the background
