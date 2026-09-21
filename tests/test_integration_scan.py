"""
End-to-end scan against a local server.

Exercises the real path — netconfig session, async checker, verifier, location
annotation — rather than calling the detection helpers directly.
"""

import http.server
import socket
import threading

import pytest

from osint import location
from osint.checker import check_username
from osint.verifier import run_local_verifier

PROFILE_HTML = b"""<html><head>
<meta property="og:title" content="Jane Roe (@janeroe)">
<meta property="og:image" content="https://cdn.example.com/a.jpg">
</head><body>
<span class="profile-location">Auckland, New Zealand</span>
<a href="https://github.com/janeroe">github</a>
</body></html>"""

NOT_FOUND_HTML = b"""<html><head>
<meta property="og:title" content="Not Found">
</head><body>Sorry, that page doesn't exist</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith("/janeroe"):
            body, status = PROFILE_HTML, 200
        else:
            body, status = NOT_FOUND_HTML, 404
        self.send_response(status)
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
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield port
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def platforms(server):
    return {
        "LocalTest": {
            "url": f"http://127.0.0.1:{server}/{{username}}",
            "method": "og_meta",
            "og_not_found": ["Not Found"],
            "category": "social", "color": "#e879f9",
            "bio_extract": True,
            "bio_patterns": {"github": r"github\.com/([a-zA-Z0-9_\-]{1,100})"},
        }
    }


@pytest.mark.asyncio
async def test_existing_profile_is_found_with_bio_and_avatar(platforms):
    results = await check_username("janeroe", platforms=platforms)
    results, purged = run_local_verifier(results, "janeroe")

    assert len(results) == 1
    assert results[0]["found"] is True
    assert results[0]["og_title"] == "Jane Roe (@janeroe)"
    assert results[0]["bio_links"] == {"github": "janeroe"}
    assert results[0]["avatar_url"] == "https://cdn.example.com/a.jpg"
    assert purged == []


@pytest.mark.asyncio
async def test_missing_profile_is_not_found(platforms):
    results = await check_username("ghost", platforms=platforms)
    results, _ = run_local_verifier(results, "ghost")
    assert results[0]["found"] is False


@pytest.mark.asyncio
async def test_progress_callback_fires_for_every_platform(platforms):
    seen = []
    await check_username("janeroe", platforms=platforms,
                         progress_cb=lambda done, total: seen.append((done, total)))
    assert seen == [(1, 1)]


@pytest.mark.asyncio
async def test_location_conflict_surfaces_on_a_real_scan(platforms):
    results = await check_username("janeroe", platforms=platforms)
    results, _ = run_local_verifier(results, "janeroe")
    location.annotate_locations(results)

    conflicts = location.flag_conflicts(results, "London, United Kingdom")

    assert len(conflicts) == 1
    assert conflicts[0]["platform"] == "LocalTest"
    assert conflicts[0]["stated"] == ["New Zealand"]
    assert results[0]["location_conflict"] is True
    assert results[0]["found"] is True  # flagged, never purged


@pytest.mark.asyncio
async def test_matching_location_produces_no_conflict(platforms):
    results = await check_username("janeroe", platforms=platforms)
    results, _ = run_local_verifier(results, "janeroe")
    location.annotate_locations(results)

    assert location.flag_conflicts(results, "Wellington, New Zealand") == []
