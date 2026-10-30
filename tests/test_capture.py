"""--save-pages: the exact page behind every reported account, hashed and checkable."""

import asyncio
import http.server
import os
import socket
import threading

import pytest

from osint import capture, checker, evidence


# snapshot

def test_snapshot_drops_session_headers_and_marks_truncation():
    snap = capture.snapshot(200, "https://x.test/api?u=jane", "https://x.test/jane",
                            [("Date", "Wed, 29 Oct 2026 10:00:00 GMT"), ("Set-Cookie", "sid=secret"),
                             ("Content-Type", "text/html")], b"a" * 10, cap=10)
    names = [h[0].lower() for h in snap["headers"]]
    assert "set-cookie" not in names and "date" in names
    assert snap["truncated"] is True and snap["body"] == b"a" * 10
    assert snap["fetched_utc"].endswith("+00:00")


def test_snapshot_accepts_mapping_headers():
    snap = capture.snapshot(200, "u", "u", {"Server": "x"}, b"ok", cap=100)
    assert snap["headers"] == [["Server", "x"]] and snap["truncated"] is False


# save / verify

def _captures():
    return {
        "Alpha": capture.snapshot(200, "https://a.test/jane", "https://a.test/jane",
                                  [("Server", "a")], b"<html>Alpha jane</html>", cap=1000),
        "Beta/Two": capture.snapshot(200, "https://b.test/api", "https://b.test/api",
                                     [("Server", "b")], b'{"user":"jane"}', cap=1000),
        "Gamma": capture.snapshot(200, "https://g.test/jane", "https://g.test/jane",
                                  [], b"purged later", cap=1000),
    }


def _results():
    return [{"platform": "Alpha", "url": "https://a.test/jane", "found": True},
            {"platform": "Beta/Two", "url": "https://b.test/jane", "found": True},
            {"platform": "Gamma", "url": "https://g.test/jane", "found": False}]   # purged after capture


def test_save_writes_only_reported_accounts_and_annotates_results(tmp_path):
    results = _results()
    m = capture.save(str(tmp_path), "jane", "jane", results, _captures())
    pdir = tmp_path / "jane_pages"
    files = sorted(os.listdir(pdir))
    assert files == ["001_Alpha.txt", "002_Beta_Two.txt", "index.html", "manifest.json"]
    assert (pdir / "001_Alpha.txt").read_bytes() == b"<html>Alpha jane</html>"
    assert results[0]["page_sha256"] == capture.sha256(b"<html>Alpha jane</html>")
    assert results[0]["page_file"] == "jane_pages/001_Alpha.txt"
    assert "page_sha256" not in results[2]
    assert len(m["pages"]) == 2 and m["_sha256"] == capture.sha256((pdir / "manifest.json").read_bytes())


def test_save_returns_none_when_nothing_was_found(tmp_path):
    assert capture.save(str(tmp_path), "jane", "jane", [_results()[2]], _captures()) is None
    assert not os.listdir(tmp_path)


def test_verify_catches_edited_missing_and_swapped_pages(tmp_path):
    m = capture.save(str(tmp_path), "jane", "jane", _results(), _captures())
    pdir = m["_dir"]
    assert capture.verify(pdir, m["_sha256"]) == []

    with open(os.path.join(pdir, "001_Alpha.txt"), "ab") as f:
        f.write(b" ")
    assert any("changed since capture" in p for p in capture.verify(pdir))

    os.remove(os.path.join(pdir, "002_Beta_Two.txt"))
    assert any("missing page" in p for p in capture.verify(pdir))

    assert capture.verify(pdir, "0" * 64)[0].startswith("manifest does not match")


def test_index_escapes_everything_and_blocks_scripts(tmp_path):
    caps = {"<b>X</b>": capture.snapshot(200, "u", "javascript:alert(1)", [], b"x", cap=10)}
    capture.save(str(tmp_path), "jane", "<i>jane</i>", [{"platform": "<b>X</b>", "found": True}], caps)
    page = (tmp_path / "jane_pages" / "index.html").read_text()
    assert "<b>X</b>" not in page and "<i>jane</i>" not in page
    assert "default-src 'none'" in page


# through the evidence file

def test_evidence_records_the_manifest_and_verification_rechecks_pages(tmp_path, capsys):
    results = _results()
    pages = capture.save(str(tmp_path), "jane", "jane", results, _captures())
    ev = evidence.write(str(tmp_path), "jane", dict(
        username="jane", results=results, platform_map={r["platform"]: {} for r in results},
        started="s", finished="f", wall_seconds=1.0, argv=["helix"], concurrency=60,
        control=True, pages=pages))
    assert ev["pages"]["count"] == 2 and ev["pages"]["manifest_sha256"] == pages["_sha256"]
    alpha = next(p for p in ev["per_site"] if p["platform"] == "Alpha")
    assert alpha["page_sha256"] == results[0]["page_sha256"]

    assert evidence.main([ev["_paths"]["evidence"], ev["_paths"]["sites"]]) == 0
    assert "re-hashed, all intact" in capsys.readouterr().out

    with open(os.path.join(pages["_dir"], "001_Alpha.txt"), "ab") as f:
        f.write(b"!")
    assert evidence.main([ev["_paths"]["evidence"]]) == 1


# end to end through check_username

class _Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        user = self.path.rsplit("/", 1)[-1]
        found = user == "janeroe"
        body = (f"<html><title>{user}</title>Profile of {user}</html>" if found else "nope").encode()
        self.send_response(200 if found else 404)
        self.send_header("Set-Cookie", "sid=abc")
        self.send_header("X-Test", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def site():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Site)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield port
    httpd.shutdown(); httpd.server_close()


def _plats(port):
    return {"Local": {"url": f"http://127.0.0.1:{port}/{{username}}", "method": "status_code",
                      "found": [200], "category": "other", "color": "#fff"}}


def test_hits_carry_the_raw_page_only_when_capture_is_on(site):
    plats = _plats(site)
    on = asyncio.run(checker.check_username("janeroe", platforms=plats, control=True, capture=True))
    off = asyncio.run(checker.check_username("janeroe", platforms=plats, control=True))
    miss = asyncio.run(checker.check_username("nobody1", platforms=plats, control=False, capture=True))
    assert on[0]["found"] and on[0]["_capture"]["body"] == b"<html><title>janeroe</title>Profile of janeroe</html>"
    assert ["X-Test", "1"] in on[0]["_capture"]["headers"]
    assert all(h[0].lower() != "set-cookie" for h in on[0]["_capture"]["headers"])
    assert "_capture" not in off[0]
    assert "_capture" not in miss[0]


def test_cli_flags_exist():
    import helix
    import sys
    sys.argv = ["helix", "--help"]
    src = open(helix.__file__).read()
    assert "--save-pages" in src and "--verify-pages" in src
