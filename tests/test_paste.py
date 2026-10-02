"""Paste intelligence: failures are 'not checked', never 'no mentions'."""

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
        if "/gists" in self.path:
            code, body = 200, [{"id": "g1", "html_url": "https://gist.github.com/g1",
                                "description": "notes", "files": {"a.md": {}},
                                "created_at": "2024-01-02T00:00:00Z"}]
        elif "down" in self.path:
            code, body = 503, {}
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
    assert r["status"] == {"gists": "ok", "pastebin (username)": "ok", "pastebin (email)": "ok"}
    assert r["gists"][0]["url"] == "https://gist.github.com/g1"
    assert r["username_pastes"][0]["url"] == "https://pastebin.com/AbCd1234"
    assert r["total"] == 3
    assert any("/users/jane%20roe%2Fx/gists" in p for p in Handler.paths)


@pytest.mark.asyncio
async def test_outage_is_not_checked(server):
    r = await paste.run("down")
    assert r["status"]["pastebin (username)"] == "not checked — HTTP 503"
    assert r["username_pastes"] == []
