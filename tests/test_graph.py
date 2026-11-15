import base64
import re

from helix_osint.graph import generate_graph


def _render(tmp_path):
    path = tmp_path / "g.html"
    generate_graph(username="janeroe", results=[
        {"platform": "GitHub", "url": "https://github.com/janeroe", "category": "dev",
         "color": "#fff", "found": True, "confidence": "high", "bio_links": {},
         "source": "builtin"},
    ], output_path=str(path))
    return path.read_text(encoding="utf-8")


def test_every_external_script_has_a_well_formed_sri_digest(tmp_path):
    """Regression: a 63-byte 'sha512' digest made browsers refuse D3: blank graph."""
    html = _render(tmp_path)
    tags = re.findall(r'<script[^>]+src="https?://[^"]+"[^>]*>', html)
    assert tags, "graph should load d3 from a CDN"
    sizes = {"sha256": 32, "sha384": 48, "sha512": 64}
    for tag in tags:
        m = re.search(r'integrity="(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)"', tag)
        assert m, f"external script without SRI: {tag}"
        algo, digest = m.groups()
        assert len(base64.b64decode(digest)) == sizes[algo], f"malformed {algo} digest in {tag}"
        assert 'crossorigin="anonymous"' in tag


def test_d3_is_pinned_to_an_exact_version(tmp_path):
    html = _render(tmp_path)
    assert re.search(r'd3@\d+\.\d+\.\d+/dist/d3\.min\.js', html)


def test_pinned_digest_matches_d3_7_8_5():
    """The digest of d3@7.8.5/dist/d3.min.js from the npm registry tarball."""
    import helix_osint.graph as g
    src = open(g.__file__, encoding="utf-8").read()
    assert "sha512-M7nHCiNUOwFt6Us3r8alutZLm9qMt4s9951uo8jqO4UwJ1hziseL6O3ndFyigx6+LREfZqnhHxYjKRJ8ZQ69DQ==" in src
    assert "d3@7.8.5" in src


def test_profile_text_cannot_close_the_graph_script(tmp_path):
    """og:title comes from the scanned page, it must not break out of <script>."""
    import json as _json
    import os as _os
    from helix_osint.graph import generate_graph as _gen
    evil = "</script><script>alert(1)</script> & <!--"
    r = [{"platform": "X", "url": "https://x.com/a", "category": "social", "color": "#fff",
          "found": True, "og_title": evil}]
    out = _os.path.join(tmp_path, "g.html")
    _gen("a", r, out)
    page = open(out).read()
    assert "<script>alert" not in page and "<!--" not in page.split("const NODES=")[1]
    nodes = _json.loads(page.split("const NODES=")[1].split(";\n")[0])
    assert any(n.get("og_title") == evil for n in nodes)        # data survives intact


def test_graph_fits_large_layouts_to_the_window(tmp_path):
    """Live: an 83-node graph settled wider than the window (nodes off-screen)."""
    import os as _os
    from helix_osint.graph import generate_graph as _gen
    out = _os.path.join(tmp_path, "g.html")
    _gen("a", [], out)
    page = open(out).read()
    assert "function fitView(" in page and 'sim.on("end"' in page
    assert "function resetZoom(){fitView(500);}" in page


def test_username_and_email_are_escaped_in_the_graph_page(tmp_path):
    from helix_osint.graph import generate_graph
    out = tmp_path / "g.html"
    generate_graph(username="<b>x</b>", results=[], output_path=str(out), email="<i>@y.z")
    page = out.read_text()
    assert "<b>x</b>" not in page and "<i>@y.z" not in page
    assert "&lt;b&gt;x&lt;/b&gt;" in page


# One meaning of confidence, and no red "Errors"

def _graph(tmp_path, results):
    path = tmp_path / "g.html"
    generate_graph(username="janeroe", results=results, output_path=str(path))
    return path.read_text(encoding="utf-8")


def _acc(platform, **kw):
    return {"platform": platform, "url": f"https://{platform.lower()}.example/janeroe", "category": "dev",
            "color": "#fff", "found": True, "bio_links": {}, "source": "builtin", **kw}


def test_the_graph_grades_accounts_like_the_web_page_and_the_report(tmp_path):
    """Found on a real scan: the page showed "Same person? LOW" for two
    accounts and the graph showed "High (OG verified) 2" for the same two.
    The graph counted how sure Helix was of the page; everything else says
    how strongly the account is tied to the others."""
    import json
    html = _graph(tmp_path, [
        _acc("PageVerified", confidence="high", identity_confidence="LOW"),      # the page was verified, the person was not
        _acc("Corroborated", confidence="medium", identity_confidence="HIGH"),
        _acc("Partly", confidence="low", identity_confidence="MEDIUM"),
        _acc("Ungraded", confidence="high"),
    ])
    assert "OG verified" not in html and "Same person?" in html
    panel = html.split('<div class="sp-title">Same person?</div>', 1)[1].split("</div>\n    </div>", 1)[0]
    counts = re.findall(r'</div>(High|Medium|Low)</div><span[^>]*>(\d+)</span>', panel)
    assert counts == [("High", "1"), ("Medium", "1"), ("Low", "2")]
    nodes = json.loads(re.search(r"const NODES\s*=\s*(\[.*?\]);", html, re.S).group(1))
    grades = {n["label"]: n["confidence"] for n in nodes if n.get("type") == "platform"}
    assert grades == {"PageVerified": "low", "Corroborated": "high", "Partly": "medium", "Ungraded": "low"}


def test_sites_without_a_clear_answer_are_grey_not_red_errors(tmp_path):
    html = _graph(tmp_path, [
        _acc("Found", identity_confidence="LOW"),
        {**_acc("Clean"), "found": False, "error": None, "status_code": 404},
        {**_acc("Timeout"), "found": False, "error": "timeout"},
        {**_acc("Refused"), "found": False, "error": None, "status_code": 403},
    ])
    assert ">Errors<" not in html
    assert '<div class="stat-box grey"><div class="sv">2</div><div class="sl">No clear answer</div></div>' in html
    assert ".stat-box.grey .sv{color:var(--dim);}" in html


def test_the_checked_count_says_when_sites_were_left_out(tmp_path):
    path = tmp_path / "g.html"
    results = [_acc("Found", identity_confidence="LOW")] * 54
    generate_graph(username="janeroe", results=results, output_path=str(path), left_out=2)
    html = path.read_text(encoding="utf-8")
    assert '>54</div><div class="sl">Checked (2 left out)</div>' in html
    assert '<div class="sl">Checked</div>' in _graph(tmp_path, results)
