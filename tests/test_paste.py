"""Paste intelligence: failures are 'not checked', never 'no mentions'.

Pastebin text search (psbdmp.ws) shut down in 2026; it must be reported as
not checked, with the reason, never silently dropped.
"""

import http.server
import json
import socket
import threading

import pytest

from osint.modules import paste


class Handler(http.server.BaseHTTPRequestHandler):
    paths = []

    def do_GET(self):
        Handler.paths.append(self.path)
        if "down" in self.path:
            code, body = 503, {}
        elif "/gists" in self.path:
            code, body = 200, [{"id": "g1", "html_url": "https://gist.github.com/g1",
                                "description": "notes", "files": {"a.md": {}},
                                "created_at": "2024-01-02T00:00:00Z"}]
        else:
            code, body = 200, {"data": [{"id": "AbCd1234", "time": "2024-02-03", "size": 10}]}
        data = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def server(monkeypatch):
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    real = paste._get_json

    async def local(session, url, headers):
        url = url.replace("https://api.github.com", base).replace("https://psbdmp.ws", base)
        return await real(session, url, headers)
    monkeypatch.setattr(paste, "_get_json", local)
    Handler.paths = []
    yield base
    httpd.shutdown(); httpd.server_close()


@pytest.mark.asyncio
async def test_results_and_escaping(server):
    r = await paste.run("jane roe/x", "jane@example.com")
    assert r["status"]["gists"] == "ok"
    assert r["gists"][0]["url"] == "https://gist.github.com/g1"
    assert r["username_pastes"] == [] and r["email_pastes"] == []
    assert r["total"] == 1
    assert any("/users/jane%20roe%2Fx/gists" in p for p in Handler.paths)


@pytest.mark.asyncio
async def test_pastebin_search_is_reported_as_not_checked(server):
    r = await paste.run("jane")
    state = r["status"]["pastebin"]
    assert state.startswith("not checked: ") and "psbdmp.ws" in state and "--sherlock" in state
    assert not any("psbdmp" in p for p in Handler.paths)     # nothing sent to the dead host


@pytest.mark.asyncio
async def test_outage_is_not_checked(server):
    r = await paste.run("down")
    assert r["status"]["gists"] == "not checked: HTTP 503"
    assert r["gists"] == [] and r["total"] == 0


@pytest.mark.asyncio
async def test_connection_errors_keep_their_cause(monkeypatch):
    """The laptop run showed '... ssl:default [No address' (cut at 60)."""
    import aiohttp

    class _Session:
        def get(self, *a, **kw):
            raise aiohttp.ClientConnectorError(
                connection_key=type("K", (), {"host": "api.github.com", "port": 443, "ssl": True})(),
                os_error=OSError(-2, "Name or service not known"))
    items, err = await paste._get_json(_Session(), "https://api.github.com/x", {})
    assert items is None and "Name or service not known" in err
