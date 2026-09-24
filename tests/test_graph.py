import base64
import re

from osint.graph import generate_graph


def _render(tmp_path):
    path = tmp_path / "g.html"
    generate_graph(username="janeroe", results=[
        {"platform": "GitHub", "url": "https://github.com/janeroe", "category": "dev",
         "color": "#fff", "found": True, "confidence": "high", "bio_links": {},
         "source": "builtin"},
    ], output_path=str(path))
    return path.read_text(encoding="utf-8")


def test_every_external_script_has_a_well_formed_sri_digest(tmp_path):
    """Regression: a 63-byte 'sha512' digest made browsers refuse D3 — blank graph."""
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
    import osint.graph as g
    src = open(g.__file__, encoding="utf-8").read()
    assert "sha512-M7nHCiNUOwFt6Us3r8alutZLm9qMt4s9951uo8jqO4UwJ1hziseL6O3ndFyigx6+LREfZqnhHxYjKRJ8ZQ69DQ==" in src
    assert "d3@7.8.5" in src
