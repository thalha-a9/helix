"""
helix --learn URL: Helix works out a site's rule from its profile address.

Each stand-in site below says "no such user" in a different way. The learner
must find the rule that fits, prove it with the control probe, and refuse to
learn anything from a site that cannot tell names apart.
"""

import argparse
import http.server
import json
import socket
import threading

import pytest

from helix_osint import cli as helix
import helix_osint.checker as ck
from helix_osint import learn, sources
from helix_osint.checker import check_username
from helix_osint.platform_schema import problems

USERS = {"alice", "john"}


def _page(title, body):
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        kind, _, name = path.strip("/").partition("/")
        name = name.split("?")[0]
        real = name.lower() in USERS
        headers = {}
        if kind == "status":
            # Plain: a profile is 200, anything else 404.
            status, body = (200, _page(name, f"<h1>{name}</h1> 42 posts")) if real else \
                (404, _page("Not Found", "Nothing here"))
        elif kind == "api":
            # A JSON API that never repeats the name it was asked for.
            status, body = (200, '{"id": 7, "posts": 42}') if real else (404, '{"error": "no"}')
        elif kind == "soft":
            # Always 200; nobody gets a page that says so.
            status = 200
            body = _page(f"{name} | Forum", f"<h1>{name}</h1><p>Member since 2019</p>") if real else \
                _page("Forum", "<div class='err'>This member does not exist.</div><a href='/'>Home</a>")
        elif kind == "json":
            # Always 200, JSON either way.
            status = 200
            body = json.dumps({"ok": True, "user": {"login": name, "id": 3}}, separators=(",", ":")) if real \
                else '{"ok":true,"user":null}'
        elif kind == "redirect":
            if real:
                status, body = 200, _page("Profile", "<p>Welcome back</p>")
            else:
                status, body, headers = 302, "", {"Location": "/redirect-missing"}
        elif path == "/redirect-missing":
            status, body = 200, _page("Join us", "<p>Create your account</p>")
        elif kind == "any":
            status, body = 200, _page(name, f"<h1>{name}</h1> profile")       # finds everyone
        elif kind == "wall":
            status, body = 403, _page("Forbidden", "no")
        elif kind == "empty":
            status, body = 404, _page("Not Found", "Nothing here")            # has no users at all
        else:
            status, body = 404, "?"
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

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


async def scan(username, name, pdef):
    return (await check_username(username, platforms={name: pdef}))[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,method,detail", [
    ("status", "status_code", {"found": [200]}),
    ("api", "status_code", {"found": [200], "name_in_page": False}),
    ("soft", "text_not_present", {"not_found_text": "This member does not exist."}),
    ("json", "text_present", {"found_text": '"login":"{username}"'}),
    ("redirect", "response_url", None),
])
async def test_each_kind_of_site_gets_the_rule_that_fits(base, kind, method, detail):
    result = await learn.learn(f"{base}/{kind}/{{username}}", known="alice")
    assert result.ok, result.why
    pdef = result.pdef
    assert pdef["method"] == method and pdef["known"] == "alice" and problems(pdef) == []
    for key, value in (detail or {}).items():
        assert pdef[key] == value
    if method == "response_url":
        assert pdef["error_url"] == f"{base}/redirect-missing"
    # The learned rule works for an account it was never shown, and for nobody.
    assert (await scan("john", result.name, pdef))["found"] is True
    assert (await scan("zq8rk2vx0bnm", result.name, pdef))["found"] is False
    assert result.steps[-1].startswith("Checked: alice found and confirmed by the control probe")


@pytest.mark.asyncio
async def test_without_a_known_account_common_names_are_tried(base):
    result = await learn.learn(f"{base}/soft/{{username}}")
    assert result.ok and result.known == "john" and not result.known_given
    assert result.pdef["known"] == "john" and result.pdef["method"] == "text_not_present"
    assert any("found by trying common names" in s for s in result.steps)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,known,why", [
    ("any", "alice", "no rule separates alice from a made-up name"),
    ("wall", "alice", "the site gives no clear answer for a made-up name (HTTP 403)"),
    ("empty", None, "none of the common names tried has an account"),
    ("status", "nobody-by-this-name", "no rule separates nobody-by-this-name from a made-up name"),
])
async def test_nothing_is_learned_from_a_site_that_cannot_tell_names_apart(base, kind, known, why):
    result = await learn.learn(f"{base}/{kind}/{{username}}", known=known)
    assert not result.ok and result.pdef == {} and why in result.why


@pytest.mark.asyncio
@pytest.mark.parametrize("url,why", [
    ("https://example.com/profile", "url has no {username}"),
    ("ftp://example.com/{username}", "url is not http(s)"),
    ("https://example.com/search?q={username}", "search page"),
])
async def test_an_address_that_cannot_be_a_profile_is_refused_before_any_request(url, why):
    result = await learn.learn(url, known="alice")
    assert not result.ok and why in result.why and result.negatives == []


def test_the_site_is_named_after_its_host():
    assert learn.site_name("https://www.Example.com/u/{username}") == "example.com"
    assert learn.site_name("https://{username}.example.org/") == "x.example.org"


def test_a_rule_is_explained_in_plain_words():
    assert learn.explain({"method": "status_code", "found": [200]}) == \
        "an account exists when the page answers HTTP 200 and names the user"
    assert "does not say 'No such member'" in learn.explain(
        {"method": "text_not_present", "not_found_text": "No such member"})


# The user's own list

def test_a_learned_site_is_one_line_in_the_users_list(tmp_path):
    path = tmp_path / "cfg" / "sites.json"
    one = {"url": "https://b.example/{username}", "method": "status_code", "found": [200], "known": "al"}
    two = {"url": "https://a.example/{username}", "method": "text_present", "found_text": '"u":"{username}"'}
    sources.save_own("b.example", one, path)
    sources.save_own("a.example", two, path)
    text = path.read_text()
    assert text.count("\n") == 4 and text.splitlines()[1].startswith(' "a.example": {')
    assert sources.read_sites(path) == {"a.example": two, "b.example": one}
    sources.save_own("b.example", {**one, "known": "bo"}, path)          # learning again replaces it
    assert sources.read_sites(path)["b.example"]["known"] == "bo" and len(sources.read_sites(path)) == 2


def test_a_broken_list_is_ignored_and_bad_entries_are_left_out(tmp_path):
    path = tmp_path / "sites.json"
    assert sources.read_sites(path) == {}
    path.write_text("not json")
    assert sources.read_sites(path) == {}
    path.write_text(json.dumps({"good": {"url": "https://g.example/{username}", "method": "status_code"},
                                "bad": {"url": "https://b.example/{username}", "method": "text_present"},
                                "odd": "x"}))
    assert list(sources.read_sites(path)) == ["good"]


@pytest.mark.asyncio
async def test_own_sites_come_first_and_replace_a_database_entry(tmp_path):
    mine = {"url": "https://github.com/{username}", "method": "status_code", "found": [200],
            "category": "dev", "color": "#fff", "source": "own"}
    path = tmp_path / "sites.json"
    sources.save_own("My GitHub", mine, path)
    seen = []
    pm = await sources.load(own_file=path, on_merged=lambda label, c, total: seen.append((label, c["added"])))
    assert list(pm)[0] == "My GitHub" and "GitHub" not in pm        # same address: mine wins
    assert seen == [("Your sites", 1)]
    plain = await sources.load(own_file=tmp_path / "none.json")
    assert "GitHub" in plain and "My GitHub" not in plain


def test_the_shipped_list_holds_only_sound_definitions_with_a_known_account():
    data = json.loads(sources.SHIPPED_SITES.read_text())
    assert isinstance(data, dict)
    for name, pdef in data.items():
        assert problems(pdef) == [], name
        assert pdef.get("known"), f"{name} has no known account for the daily site check"
    assert sources.read_sites(sources.SHIPPED_SITES) == data


# The command

def _args(**kw):
    base = dict(learn=None, known=None, site_name=None, sites_file=None)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.asyncio
async def test_the_command_learns_saves_and_prints_the_line(base, tmp_path, capsys):
    path = tmp_path / "mine.json"
    code = await helix.learn_site(_args(learn=f"{base}/status/{{username}}", known="@alice",
                                        site_name="Standin", sites_file=str(path)))
    out = capsys.readouterr().out
    assert code == 0
    assert "Made-up names: HTTP 404, HTTP 404, HTTP 404" in out
    assert "Rule: an account exists when the page answers HTTP 200 and names the user" in out
    assert f"Saved as" in out and str(path) in out
    saved = sources.read_sites(path)["Standin"]
    assert saved["known"] == "alice" and saved["source"] == "own"
    line = next(l for l in out.splitlines() if l.strip().startswith('"Standin": {'))
    assert json.loads("{" + line + "}") == {"Standin": saved}


@pytest.mark.asyncio
async def test_the_command_says_why_nothing_was_learned(base, tmp_path, capsys):
    path = tmp_path / "mine.json"
    code = await helix.learn_site(_args(learn=f"{base}/any/{{username}}", known="alice",
                                        sites_file=str(path)))
    out = capsys.readouterr().out
    assert code == 1 and "Nothing learned: no rule separates alice from a made-up name" in out
    assert not path.exists()
    assert await helix.learn_site(_args(learn=f"{base}/status/{{username}}", known="bad name!")) == 1
