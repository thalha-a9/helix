"""--fediverse: about 3,900 live-tested Mastodon, Misskey, Lemmy and PeerTube servers."""

import http.server
import json
import os
import socket
import sys
import threading

import pytest

from osint.adapters import fediverse_adapter as fa
from osint.checker import check_username
from osint.fediverse_servers import GENERATED, SERVERS
from osint.platform_schema import filter_valid


def test_the_shipped_list_is_sound():
    assert len(SERVERS) > 3000 and GENERATED
    domains = [d for d, _ in SERVERS]
    assert len(domains) == len(set(domains))
    assert all(d == d.lower() and "/" not in d and " " not in d for d in domains)
    usable, unusable = filter_valid(fa.load_platforms(include_nsfw=True))
    assert not unusable and len(usable) == len(SERVERS)


def test_adult_servers_need_nsfw():
    default = fa.load_platforms()
    everything = fa.load_platforms(include_nsfw=True)
    listed = {d for d, _ in SERVERS} & fa.NSFW
    assert listed and not listed & set(default)
    assert listed <= set(everything)
    assert all(everything[d].get("nsfw") for d in listed)


def test_servers_already_covered_are_skipped():
    some = SERVERS[0][0]
    assert some not in fa.load_platforms(skip_hosts=[some.upper()])


def test_unknown_software_gets_no_definition():
    assert fa.platform_for("x.example", "wordpress") == {}


def test_host_of():
    assert fa.host_of("https://www.Example.social:443/@{username}") == "example.social"


# Live behaviour against local stand-ins

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path.startswith("/api/v1/accounts/lookup?acct="):
            name = path.split("=", 1)[1]
            if name.lower() == "janeroe":
                status, body = 200, json.dumps({"id": "1", "username": "janeroe", "acct": "janeroe"}, separators=(",", ":"))
            else:
                status, body = 404, '{"error":"Record not found"}'
        elif path.startswith("/@"):
            name = path[2:]
            title = "Jane Roe (@janeroe)" if name == "janeroe" else "misskey.example"
            status, body = 200, f'<html><head><meta property="og:title" content="{title}"></head></html>'
        else:
            status, body = 404, "not found"
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base():
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{port}"
    httpd.shutdown(); httpd.server_close()


def _local(pdef, host):
    return {k: (v.replace(f"https://{host}", f"http://{host}") if isinstance(v, str) else v) for k, v in pdef.items()}


@pytest.mark.asyncio
@pytest.mark.parametrize("software", ["mastodon", "akkoma", "misskey", "sharkey"])
async def test_real_user_found_and_made_up_user_not(base, software):
    platforms = {"Server": _local(fa.platform_for(base, software), base)}
    found = await check_username("janeroe", platforms=platforms)
    assert found[0]["found"] is True
    missing = await check_username("qzx8kfn3vbq2", platforms=platforms)
    assert missing[0]["found"] is False


def test_update_tool_writes_an_importable_list(tmp_path):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    try:
        import update_fediverse
    finally:
        sys.path.pop(0)
    out = tmp_path / "servers.py"
    n = update_fediverse.write_module([{"domain": "b.example", "software": "mastodon"},
                                       {"domain": "a.example", "software": "lemmy"},
                                       {"domain": "a.example", "software": "lemmy"}], str(out))
    ns = {}
    exec(out.read_text(), ns)
    assert n == 2 and ns["SERVERS"] == (("a.example", "lemmy"), ("b.example", "mastodon"))
