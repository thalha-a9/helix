"""Certificate transparency: exact-name domains only, failures never read as 'none'."""

import http.server
import json
import socket
import threading

import pytest

from osint.modules import crt

# Names from the live crt.sh answer for "krisnova.%" (Oct 2026)
LIVE_NAMES = ["krisnova.co.uk", "*.krisnova.com", "krisnova.com.mx", "krisnova.edumer.org",
              "krisnova.freepornmodels.com", "krisnova.fun", "krisnova.lovelycamgirls.com",
              "www.krisnova.net", "krisnova.nft.nyc", "krisnova.org", "krisnova.pinkporntube.com",
              "krisnova.vallas-moviles.mx", "krisnovah.com", "krisnovahealthcare.com"]


def _certs(names, extra=""):
    return [{"name_value": n + extra, "common_name": n} for n in names]


@pytest.mark.parametrize("name,want", [
    ("www.krisnova.co.uk", "krisnova.co.uk"), ("*.krisnova.com", "krisnova.com"),
    ("krisnova.com.mx", "krisnova.com.mx"), ("krisnova.freepornmodels.com", "freepornmodels.com"),
    ("a.b.example.org", "example.org"), ("bad_label.com", None), ("localhost", None),
])
def test_registered_domain(name, want):
    assert crt.registered_domain(name) == want


def test_only_domains_named_exactly_after_the_username():
    got = crt.named_after(_certs(LIVE_NAMES), "krisnova")
    assert set(got) == {"krisnova.co.uk", "krisnova.com", "krisnova.com.mx", "krisnova.fun",
                        "krisnova.net", "krisnova.org"}


def test_email_certificates_link_their_domains():
    certs = [{"name_value": "jane@roe.dev\nmail.roe.dev", "common_name": "roe.dev"},
             {"name_value": "other@else.com\nelse.com", "common_name": "else.com"}]
    assert crt.on_email_certs(certs, "Jane@Roe.dev") == ["roe.dev"]


class Handler(http.server.BaseHTTPRequestHandler):
    calls = 0

    def do_GET(self):
        Handler.calls += 1
        if "down" in self.path:
            self.send_response(502); self.end_headers(); return
        body = json.dumps(_certs(["janeroe.dev", "janeroe2.com"])).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def server(monkeypatch):
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setattr(crt, "RETRY_DELAY", 0)
    Handler.calls = 0
    yield f"http://127.0.0.1:{port}/"
    httpd.shutdown(); httpd.server_close()


@pytest.mark.asyncio
async def test_run_reports_domains(server, monkeypatch):
    monkeypatch.setattr(crt, "CRT_URL", server)
    r = await crt.run("janeroe")
    assert r["status"] == {"username": "ok"} and r["named_domains"] == ["janeroe.dev"]


@pytest.mark.asyncio
async def test_crt_outage_is_not_checked_never_empty(server, monkeypatch):
    monkeypatch.setattr(crt, "CRT_URL", server + "down")
    r = await crt.run("janeroe")
    assert r["status"]["username"] == "not checked — crt.sh HTTP 502"
    assert Handler.calls == crt.ATTEMPTS


@pytest.mark.asyncio
async def test_short_names_are_skipped():
    r = await crt.run("max")
    assert r["status"]["username"].startswith("skipped")
