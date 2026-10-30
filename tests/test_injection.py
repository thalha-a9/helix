"""Every HTML output stays inert when every third-party string is hostile.

Profile titles, bios, links, platform names, breach text, dark-web titles and
saved-page metadata all come from strangers. Fill all of them with markup and
javascript: links, render the graph, the report and the saved-pages index,
and check nothing executable survives. (Checked once in a real browser too:
no dialog fired with every node and link clicked.)
"""

import copy
import re

from osint import capture
from osint.graph import generate_graph
from osint.pdf_report import _build_html
from test_relationships import DARK, EDGE, VERDICT

X = '"><script>alert("x1")</script><img src=x onerror=alert("x2")><svg onload=alert("x3")>'
J = 'javascript:alert("x4")'
ENUM = {"confidence", "status", "relation", "target_type", "kind", "source", "match_type"}
URLISH = {"url", "onion", "domain", "final_url", "avatar_url"}
EXECUTABLE = [r"<script>alert", r"<img src=x onerror", r"<svg onload", r"href=.javascript:"]


def hostile(o, key=None):
    if isinstance(o, dict):
        return {k: (v if k in ENUM else hostile(v, k)) for k, v in o.items()}
    if isinstance(o, list):
        return [hostile(v, key) for v in o]
    if isinstance(o, str):
        return J if key in URLISH else X
    return o


def _results():
    return [{"platform": f"Site{i}{X}", "url": J if i == 0 else f"https://ex{i}.test/u{X}",
             "category": "social", "color": "#fff", "found": True, "confidence": "high",
             "og_title": X, "bio_links": {"website": J, "twitter": X}, "source": "builtin",
             "identity_confidence": "LOW", "evidence": [X], "selectors": ["username"],
             "location_hints": [X], "declared_bio": X, "avatar_url": J, "final_url": J,
             "page_file": X, "page_sha256": X, "target_type": "username"} for i in range(3)]


EMAIL = [{"platform": X, "url": J, "found": True, "category": "social", "color": "#fff",
          "target_type": "email", "source": "holehe"}]


def _assert_inert(page: str):
    for pat in EXECUTABLE:
        assert not re.search(pat, page, re.I), pat


def test_graph_is_inert(tmp_path):
    edge, verdict, dark = hostile(EDGE), hostile(VERDICT), hostile(DARK)
    dark["breaches"] = [verdict]
    res = _results()
    out = tmp_path / "g.html"
    generate_graph(username="fuzzuser", results=res, output_path=str(out), email="a@b.co",
                   email_results=EMAIL,
                   pivot_data={"aliasx": {"depth": 1, "discovered_via": X, "found": copy.deepcopy(res)}},
                   phash_matches=[{"platform_a": res[0]["platform"], "platform_b": res[1]["platform"],
                                   "confidence": "high", "match_type": "exact", "distance": 0}],
                   relationships=[edge], breach_verdicts=[verdict], darkweb=dark)
    page = out.read_text()
    _assert_inert(page)
    # Clicking a node opens http(s) only.
    assert re.search(r"/\^https\?:\\/\\//i\.test\(d\.url\)", page)


def test_report_is_inert():
    edge, verdict, dark = hostile(EDGE), hostile(VERDICT), hostile(DARK)
    page = _build_html(
        "fuzzuser", _results(), email="a@b.co", email_results=EMAIL,
        wayback_data={"Site1": {"first_seen": X, "last_seen": X, "months": X}, "y": {"error": X}},
        github_intel={"emails": [X], "orgs": [{"name": X}], "timezone": {"timezone": X},
                      "npm_packages": [{"name": X}]},
        crt_data={"all_domains": [X], "email_domains": [X], "named_domains": [X], "status": {X: X}},
        paste_data={"gists": [{"description": X, "url": J}], "username_pastes": [{"url": J}],
                    "status": {X: X}},
        phash_matches=[{"platform_a": X, "platform_b": X, "confidence": X, "match_type": X}],
        breach_verdicts=[verdict], darkweb=dark, relationships=[edge])
    _assert_inert(page)


def test_saved_pages_index_is_inert(tmp_path):
    res = _results()
    caps = {r["platform"]: capture.snapshot(200, J, J, [(X, X)], X.encode(), cap=10_000) for r in res}
    capture.save(str(tmp_path), "fuzz", X, res, caps)
    _assert_inert((tmp_path / "fuzz_pages" / "index.html").read_text())
