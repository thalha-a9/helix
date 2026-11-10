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


# An account that exists on a server, named by the server itself

class _Reply:
    def __init__(self, status, body):
        self.status, self._body = status, body.encode()
        self.content = self

    async def iter_chunked(self, n):
        yield self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Api:
    """A session whose replies are looked up by address."""
    def __init__(self, replies):
        self.replies, self.asked = replies, []

    def request(self, method, url, **kw):
        self.asked.append((method, url))
        status, payload = self.replies.get(url, (404, "{}"))
        return _Reply(status, payload if isinstance(payload, str) else json.dumps(payload))


@pytest.mark.asyncio
@pytest.mark.parametrize("software,url,payload,name", [
    ("mastodon", "https://s.example/api/v2/instance", {"contact": {"account": {"username": "evenrain"}}}, "evenrain"),
    ("pleroma", "https://s.example/api/v1/instance", {"contact_account": {"username": "lain"}}, "lain"),
    ("mastodon", "https://s.example/api/v1/directory?local=true&limit=1", [{"username": "first"}], "first"),
    ("misskey", "https://s.example/api/users", [{"username": "syuilo"}], "syuilo"),
    ("lemmy", "https://s.example/api/v3/site", {"admins": [{"person": {"name": "nutomic"}}]}, "nutomic"),
    ("peertube", "https://s.example/api/v1/accounts?count=20&sort=-createdAt",
     {"data": [{"host": "other.example", "name": "remote"}, {"host": "s.example", "name": "framasoft"}]}, "framasoft"),
    # A stranger's server cannot hand Helix something that is not a username.
    ("mastodon", "https://s.example/api/v2/instance", {"contact": {"account": {"username": "../../admin?x="}}}, None),
    ("lemmy", "https://s.example/api/v3/site", {"admins": []}, None),
    ("mastodon", "https://s.example/api/v2/instance", "<html>not json</html>", None),
    ("wordpress", "https://s.example/", {}, None),
])
async def test_a_server_names_an_account_of_its_own(software, url, payload, name):
    api = _Api({url: (200, payload)})
    assert await fa.known_account(api, "s.example", software) == name


@pytest.mark.asyncio
async def test_known_accounts_skips_servers_that_fail_or_are_not_listed(monkeypatch):
    listed = SERVERS[0][0]

    async def lookup(session, domain, software):
        if domain == listed:
            return "admin"
        raise RuntimeError("unreachable")

    monkeypatch.setattr(fa, "known_account", lookup)
    seen = []
    got = await fa.known_accounts([listed, SERVERS[1][0], "not-on-the-list.example"],
                                  progress_cb=lambda d, t: seen.append((d, t)))
    assert got == {listed: "admin"} and seen[-1] == (2, 2)
