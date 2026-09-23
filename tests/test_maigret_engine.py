"""
Maigret engine integration.

The real subprocess path is exercised with a stand-in `maigret` executable on
PATH that writes a genuine-format "simple" JSON report pointing at a local
server. The key regression: Maigret's known false positives (a site homepage
reported as a hit, a WAF page, a dead link) must never survive Helix's
verification.
"""

import http.server
import json
import os
import socket
import stat
import sys
import threading

import pytest

from osint import netconfig
from osint.adapters import maigret_engine as me
from osint.platforms import PLATFORMS
from osint.verifier import run_local_verifier, _is_homepage_only

USERNAME = "janeroe"

PAGES = {
    "/profile/janeroe": (200, b'<html><head><meta property="og:title" content="Jane Roe (@janeroe)">'
                              b'<meta property="og:image" content="https://cdn.example.com/j.png">'
                              b'</head><body>Jane Roe profile</body></html>'),
    "/": (200, b'<html><head><meta property="og:title" content="Discord - Group Chat">'
               b'</head><body>Imagine a place</body></html>'),
    "/waf/janeroe": (200, b"<html><title>Just a moment...</title>Checking your browser</html>"),
    "/gone/janeroe": (404, b"Not Found"),
    "/soft/janeroe": (200, b'<html><head><meta property="og:title" content="Oops">'
                           b'</head><body>Sorry, this user was not found</body></html>'),
    "/bounce/janeroe": (302, b""),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status, body = PAGES.get(self.path, (404, b"Not Found"))
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def claimed(url, tags=None, similar=False):
    return {
        "username": USERNAME, "url_user": url, "http_status": 200,
        "is_similar": similar,
        "status": {"username": USERNAME, "site_name": "x", "url": url,
                   "status": "Claimed", "ids": {}, "tags": tags or []},
        "site": {},
    }


@pytest.fixture
def fake_maigret(tmp_path, monkeypatch):
    """Install a stand-in maigret on PATH; returns (set_report, argv_log_path)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    argv_log = tmp_path / "argv.json"
    report_file = tmp_path / "report.json"
    script = bindir / "maigret"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "args = sys.argv[1:]\n"
        f"json.dump(args, open({str(argv_log)!r}, 'w'))\n"
        "out = args[args.index('--folderoutput') + 1]\n"
        "user = args[args.index('--') + 1]\n"
        f"data = open({str(report_file)!r}).read()\n"
        "open(os.path.join(out, f'report_{user}_simple.json'), 'w').write(data)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")

    def set_report(data):
        report_file.write_text(json.dumps(data))

    return set_report, argv_log


# ── Command construction ─────────────────────────────────────────────────────

def test_username_follows_option_terminator():
    cmd = me.build_command("maigret", "--help", "/tmp/x", 30, 500, None)
    assert cmd[-2:] == ["--", "--help"]
    assert cmd.index("--") > cmd.index("--folderoutput")


def test_no_recursion_so_scope_stays_on_the_requested_username():
    assert "--no-recursion" in me.build_command("maigret", USERNAME, "/tmp/x", 30, 500, None)


def test_proxy_is_forwarded():
    cmd = me.build_command("maigret", USERNAME, "/tmp/x", 30, 500, "socks5://127.0.0.1:9050")
    assert cmd[cmd.index("--proxy") + 1] == "socks5://127.0.0.1:9050"


def test_no_proxy_flag_when_direct():
    assert "--proxy" not in me.build_command("maigret", USERNAME, "/tmp/x", 30, 500, None)


# ── Report parsing ───────────────────────────────────────────────────────────

def test_parse_keeps_only_exact_claimed_http_hits():
    data = {
        "Keep":    claimed("https://keep.example/janeroe", tags=["coding"]),
        "Similar": claimed("https://sim.example/jane_roe", similar=True),
        "Unknown": {**claimed("https://u.example/janeroe"),
                    "status": {"status": "Unknown", "tags": []}},
        "NoUrl":   claimed("javascript:alert(1)"),
        "Junk":    "not-a-dict",
    }
    leads = me.parse_report(data, USERNAME)
    assert [l["platform"] for l in leads] == ["Keep"]
    lead = leads[0]
    assert lead["source"] == "maigret_engine"
    assert lead["confidence"] == "low"
    assert lead["category"] == "dev"


def test_parse_empty_report():
    assert me.parse_report({}, USERNAME) == []
    assert me.parse_report(None, USERNAME) == []


def test_platforms_helix_already_checked_are_dropped():
    leads = [{"platform": "GitHub"}, {"platform": "github"}, {"platform": "Twitter/X"},
             {"platform": "SomethingNew"}]
    kept = me.drop_known(leads, ["GitHub", "Twitter/X"])
    assert [l["platform"] for l in kept] == ["SomethingNew"]


# ── Homepage-only guard (the Discord false positive) ─────────────────────────

@pytest.mark.parametrize("url", [
    "https://discord.com/", "https://discord.com", "https://example.com/home",
    "https://example.com/index.html", "https://example.com/en/",
])
def test_homepage_without_username_is_flagged(url):
    assert _is_homepage_only(url, USERNAME)


@pytest.mark.parametrize("url", [
    "https://janeroe.substack.com/",
    "https://example.com/?user=janeroe",
    "https://example.com/u/janeroe",
    "https://example.com/users/12345",
])
def test_real_profile_urls_are_not_flagged(url):
    assert not _is_homepage_only(url, USERNAME)


@pytest.mark.parametrize("name,plat", list(PLATFORMS.items()), ids=list(PLATFORMS))
def test_no_builtin_profile_url_is_mistaken_for_a_homepage(name, plat):
    url = plat["url"].replace("{username}", USERNAME)
    assert not _is_homepage_only(url, USERNAME)


def test_verifier_purges_homepage_hit_even_at_high_confidence():
    r = {"platform": "Discord", "url": "https://discord.com/", "final_url": "https://discord.com/",
         "found": True, "confidence": "high", "source": "maigret_engine",
         "og_title": "Discord - Group Chat", "_page_text": "<html>Imagine a place</html>"}
    results, purged = run_local_verifier([r], USERNAME)
    assert results[0]["found"] is False
    assert "homepage-only" in purged[0]["reason"]


def test_verifier_purges_redirect_to_homepage():
    r = {"platform": "X", "url": "https://x.example/janeroe", "final_url": "https://x.example/",
         "found": True, "confidence": "high", "source": "maigret_engine",
         "og_title": "X", "_page_text": "<html>welcome</html>"}
    results, _ = run_local_verifier([r], USERNAME)
    assert results[0]["found"] is False


# ── Re-probing ───────────────────────────────────────────────────────────────

def lead(url, platform="Site"):
    return me.parse_report({platform: claimed(url)}, USERNAME)[0]


@pytest.mark.asyncio
async def test_reprobe_captures_page_for_the_verifier(server):
    [r] = await me.reprobe_leads([lead(f"{server}/profile/janeroe")])
    assert r["found"] is True
    assert r["status_code"] == 200
    assert r["og_title"] == "Jane Roe (@janeroe)"
    assert r["avatar_url"] == "https://cdn.example.com/j.png"
    assert "Jane Roe profile" in r["_page_text"]


@pytest.mark.asyncio
async def test_reprobe_drops_dead_leads(server):
    [r] = await me.reprobe_leads([lead(f"{server}/gone/janeroe")])
    assert r["found"] is False
    assert "reprobe_status: 404" in r["error"]


@pytest.mark.asyncio
async def test_reprobe_drops_waf_pages(server):
    [r] = await me.reprobe_leads([lead(f"{server}/waf/janeroe")])
    assert r["found"] is False
    assert "waf_blocked" in r["error"]


@pytest.mark.asyncio
async def test_reprobe_survives_unreachable_hosts():
    [r] = await me.reprobe_leads([lead("http://127.0.0.1:9/janeroe")])
    assert r["found"] is False
    assert r["error"].startswith("reprobe_failed")


# ── End to end through the real subprocess ───────────────────────────────────

@pytest.mark.asyncio
async def test_engine_not_installed(monkeypatch):
    monkeypatch.setattr(me, "find_maigret", lambda: None)
    out = await me.run_engine(USERNAME)
    assert "not installed" in out["error"]
    assert out["results"] == []


@pytest.mark.asyncio
async def test_only_genuine_profiles_survive_maigret_false_positives(server, fake_maigret):
    set_report, _ = fake_maigret
    set_report({
        "RealSite":   claimed(f"{server}/profile/janeroe", tags=["social"]),
        "Discord":    claimed(f"{server}/"),               # homepage "hit"
        "WafSite":    claimed(f"{server}/waf/janeroe"),
        "DeadSite":   claimed(f"{server}/gone/janeroe"),
        "SoftSite":   claimed(f"{server}/soft/janeroe"),
        "BounceSite": claimed(f"{server}/bounce/janeroe"),  # 302 → homepage
        "GitHub":     claimed(f"{server}/profile/janeroe"),  # Helix already checks it
        "Lookalike":  claimed(f"{server}/profile/jane_roe", similar=True),
    })

    out = await me.run_engine(USERNAME, known_platforms=["GitHub"])
    assert out["error"] is None
    assert out["leads"] == 7
    assert out["skipped_known"] == 1

    results, purged = run_local_verifier(out["results"], USERNAME)
    survivors = sorted(r["platform"] for r in results if r.get("found"))

    assert survivors == ["RealSite"]
    purged_names = {p["platform"] for p in purged}
    assert {"Discord", "SoftSite", "BounceSite"} <= purged_names


@pytest.mark.asyncio
async def test_engine_receives_the_configured_proxy(fake_maigret):
    set_report, argv_log = fake_maigret
    set_report({})
    netconfig.set_proxy("http://10.0.0.5:3128")
    await me.run_engine(USERNAME)
    argv = json.loads(argv_log.read_text())
    assert argv[argv.index("--proxy") + 1] == "http://10.0.0.5:3128"
    assert argv[-2:] == ["--", USERNAME]


@pytest.mark.asyncio
async def test_missing_report_is_reported_not_raised(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "maigret"
    script.write_text(f"#!{sys.executable}\nimport sys\nsys.stderr.write('boom\\n')\nsys.exit(2)\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")

    out = await me.run_engine(USERNAME)
    assert "no report" in out["error"]
    assert "boom" in out["error"]


@pytest.mark.asyncio
async def test_runaway_engine_is_stopped(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "maigret"
    script.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")

    out = await me.run_engine(USERNAME, max_runtime=1)
    assert "stopped" in out["error"]
