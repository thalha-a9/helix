"""
--json: Helix run by another program. Standard output carries exactly one
JSON object (the confirmed accounts with platform, url and confidence, and
the counts); everything a person would read goes to standard error.
"""

import http.server
import json
import os
import socket
import subprocess
import sys
import threading

import pytest

from helix_osint import cli as helix
from helix_osint import leftout, netconfig

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        kind, _, name = self.path.strip("/").partition("/")
        if kind == "good" and name == "janeroe":
            status, body = 200, b"<html>janeroe - 42 posts</html>"
        elif kind == "any":
            status, body = 200, b"<html>Profile of " + name.encode() + b"</html>"
        elif kind == "wall":
            status, body = 403, b"no"
        else:
            status, body = 404, b"<html>Not Found</html>"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def sites(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    own = tmp_path / "sites.json"
    own.write_text(json.dumps({k: {"url": f"{base}/{k.lower()}/{{username}}", "method": "status_code",
                                   "found": [200], "category": "social", "color": "#fff", "source": "own"}
                               for k in ("Good", "Any", "Wall")}))
    yield own
    server.shutdown()


def run_helix(args, cwd, sites_file=None, extra_env=None):
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env.update({"PYTHONPATH": ROOT, "HOME": str(cwd), **(extra_env or {})})
    if sites_file:
        env["HELIX_SITES"] = str(sites_file)
    return subprocess.run([sys.executable, "-m", "helix_osint", *args], capture_output=True, text=True,
                          cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, timeout=600)


def test_stdout_is_one_json_object_and_everything_else_is_on_stderr(sites, tmp_path):
    r = run_helix(["--json", "--purpose", "test", "-u", "janeroe"], tmp_path, sites)
    assert r.returncode == 0
    lines = r.stdout.splitlines()
    assert len(lines) == 1, "standard output must hold the JSON object and nothing else"
    data = json.loads(lines[0])
    assert data["schema"] == "helix.cli.v1" and data["tool"] == {"name": "Helix", "version": helix.__version__}
    assert data["username"] == "janeroe" and data["purpose"] == "test"
    good = [a for a in data["accounts"] if a["platform"] == "Good"]
    assert len(good) == 1
    assert set(good[0]) == {"platform", "url", "category", "source", "confidence", "evidence", "kind"}
    assert good[0]["url"].endswith("/good/janeroe") and good[0]["confidence"] in ("HIGH", "MEDIUM", "LOW")
    assert good[0]["kind"] == "username"
    # The site that finds everyone was discarded; the one that refused is counted, not reported.
    assert not any(a["platform"] in ("Any", "Wall") for a in data["accounts"])
    s = data["summary"]
    assert s["found"] == len(data["accounts"]) and s["answered"] + s["unanswered"] == s["attempted"]
    assert s["unanswered"] >= 2 and s["left_out"] == 0
    # What a person reads is all on standard error, colours and banner included.
    assert "Found" in r.stderr and "Scanning @janeroe" in r.stderr and "\x1b[" not in r.stdout


def test_nothing_is_asked_and_no_browser_is_opened(sites, tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(helix.webbrowser, "open", lambda *a, **k: opened.append(a))
    r = run_helix(["--json", "--permutations", "-u", "janeroe"], tmp_path, sites)
    assert r.returncode == 0 and json.loads(r.stdout)["username"] == "janeroe"
    assert "Scan all?" not in r.stderr and opened == []


@pytest.mark.parametrize("args,code,why", [
    (["--json", "-u", "jane roe"], 1, "the scan did not run"),
    (["--json"], 1, "the scan did not run"),
])
def test_a_scan_that_cannot_run_still_prints_an_object(tmp_path, args, code, why):
    r = run_helix(args, tmp_path)
    data = json.loads(r.stdout)
    assert r.returncode == code and data["exit_code"] == code and why in data["error"]
    assert data["accounts"] == [] and data["schema"] == "helix.cli.v1"
    assert len(r.stdout.splitlines()) == 1 and r.stderr.strip()


def test_a_left_out_name_is_reported_as_such(tmp_path, monkeypatch, capsys):
    shipped = tmp_path / "left.json"
    shipped.write_text(json.dumps({"schema": leftout.SCHEMA, "tokens": [leftout.token("janeroe")]}))
    monkeypatch.setattr(leftout, "SHIPPED", shipped)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(helix.sys, "argv", ["helix", "--json", "-u", "janeroe"])
    with pytest.raises(SystemExit) as stop:
        helix.main()
    out = capsys.readouterr()
    data = json.loads(out.out)
    assert stop.value.code == 3 and data["error"] == "the name is on the left-out list" and data["exit_code"] == 3
    assert "left-out list" in out.err


def test_the_machine_report_keeps_email_accounts_apart_and_lists_unconfirmed():
    results = [{"platform": "B", "url": "u2", "found": True, "identity_confidence": "HIGH",
                "evidence": ["same picture as A"], "category": "dev", "source": "builtin"},
               {"platform": "a", "url": "u1", "found": True, "category": "social", "source": "wmn"},
               {"platform": "C", "url": "u3", "found": False, "unconfirmed": True, "error": "unconfirmed: x"},
               {"platform": "D", "url": "u4", "found": False, "status_code": 404}]
    email = [{"platform": "Gravatar", "url": "g", "found": True, "target_type": "email"}]
    rep = helix.machine_report("janeroe", "j@example.com", results, email, [{"platform": "Off"}], None)
    assert [(a["platform"], a["confidence"], a["kind"]) for a in rep["accounts"]] == [
        ("a", "LOW", "username"), ("B", "HIGH", "username"), ("Gravatar", "LOW", "email")]
    assert rep["accounts"][1]["evidence"] == ["same picture as A"]
    assert rep["unconfirmed"] == [{"platform": "C", "url": "u3"}]
    assert rep["summary"]["left_out"] == 1 and rep["purpose"] == "not stated" and rep["email"] == "j@example.com"
    json.dumps(rep)


@pytest.mark.parametrize("given,used", [("socks5h://127.0.0.1:9050", "socks5"), ("socks4a://127.0.0.1:9050", "socks4")])
def test_a_socks5h_proxy_is_accepted(monkeypatch, given, used):
    """aiohttp-socks has no socks5h scheme; Helix said it took one and then
    failed on the first request. Found while wiring Helix into another tool."""
    pytest.importorskip("aiohttp_socks")
    seen = {}

    class Fake:
        @staticmethod
        def from_url(url, **kw):
            seen.update(url=url, **kw)
            return object()
    monkeypatch.setattr(netconfig, "ProxyConnector", Fake)
    netconfig.set_proxy(given)
    netconfig.build_connector(limit=5)
    assert seen["url"].startswith(used + "://") and seen["rdns"] is True
