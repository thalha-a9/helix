"""
Robin dark-web module (#20): Ahmia search and the cited-only LLM analysis.

Ahmia is replayed by a local server serving its search form (with the hidden
anti-scraping token) and a results page in Ahmia's markup.
"""

import http.server
import json
import socket
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from osint.modules import robin

ONION_A = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
ONION_B = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefgh.onion"
ONION_C = "zyxwvutsrqponmlkzyxwvutsrqponmlkzyxwvutsrqponmlkzyxwvuts.onion"

HOME = """<html><body>
<form id="searchForm" action="/search/" method="get">
  <input type="hidden" name="d41d8cd9" value="8f00b204e980">
  <input type="text" name="q">
</form></body></html>"""


def _result(onion, title, desc, ts="1720000000.0"):
    return f"""<li class="result">
  <h4><a href="/search/search/redirect?search_term=x&redirect_url=http://{onion}/page">{title}</a></h4>
  <p>{desc}</p>
  <p class="urlinfo"><cite>http://{onion}/page</cite> - <span class="lastSeen" data-timestamp="{ts}">x</span></p>
</li>"""


RESULTS = f"""<html><body><ol class="searchResults">
{_result(ONION_A, "Leak forum profile janeroe", "Posts by janeroe on the forum")}
{_result(ONION_B, "Market listing", "Vendor janeroe2000 sells stuff")}
{_result(ONION_C, "Paste", "contact jane.roe@example.com for details")}
{_result(ONION_A, "Leak forum profile janeroe", "duplicate of the first hit")}
</ol></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    queries = []

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._html(200, HOME)
        if u.path == "/search/":
            q = parse_qs(u.query)
            Handler.queries.append(q)
            if q.get("d41d8cd9") != ["8f00b204e980"]:
                return self._html(200, HOME)          # Ahmia bounces token-less searches
            term = q.get("q", [""])[0]
            if term == "challenge":
                return self._html(200, "<html>Please verify you are human</html>")
            if term == "nothing":
                return self._html(200, "<html><p>No results found for your query.</p></html>")
            return self._html(200, RESULTS)
        self._html(404, "")

    def _html(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def ahmia(monkeypatch):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    monkeypatch.setattr(robin, "AHMIA_HOME", base + "/")
    monkeypatch.setattr(robin, "AHMIA_SEARCH", base + "/search/")
    Handler.queries = []
    yield base
    httpd.shutdown()
    httpd.server_close()


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_form_tokens_are_read_from_the_search_form():
    assert robin.parse_form_tokens(HOME) == {"d41d8cd9": "8f00b204e980"}


def test_results_are_parsed():
    hits = robin.parse_results(RESULTS)
    assert len(hits) == 4
    assert hits[0]["onion"] == ONION_A
    assert hits[0]["url"] == f"http://{ONION_A}/page"
    assert hits[0]["title"] == "Leak forum profile janeroe"
    assert hits[0]["last_seen"] == "2024-07-03"


@pytest.mark.parametrize("text,term,ok", [
    ("Posts by janeroe here", "janeroe", True),
    ("Vendor janeroe2000", "janeroe", False),          # longer handle, different person
    ("mail jane.roe@example.com", "jane.roe@example.com", True),
    ("mail xjane.roe@example.com", "jane.roe@example.com", False),
    ("by Jane Roe", "Jane Roe", True),
])
def test_exact_term_match(text, term, ok):
    assert robin.mentions({"title": text}, term) is ok


# ── Search ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_search_sends_token_and_keeps_only_exact_mentions(ahmia):
    async with robin.netconfig.new_session() as s:
        out = await robin.ahmia_search(s, "janeroe")
    assert out["status"] == "ok"
    assert [h["onion"] for h in out["hits"]] == [ONION_A]       # dedup + exact match
    assert out["dropped"] == 2                                  # janeroe2000 + email paste
    assert out["hits"][0]["source"] == "Ahmia"
    assert Handler.queries[-1]["d41d8cd9"] == ["8f00b204e980"]


@pytest.mark.asyncio
async def test_empty_results_are_ok_and_unknown_pages_are_errors(ahmia):
    async with robin.netconfig.new_session() as s:
        empty = await robin.ahmia_search(s, "nothing")
        blocked = await robin.ahmia_search(s, "challenge")
    assert empty["status"] == "ok" and empty["hits"] == []
    assert blocked["status"] == "error"          # never "nothing on the dark web"


@pytest.mark.asyncio
async def test_bounce_to_homepage_is_an_error_not_zero_results(ahmia, monkeypatch):
    monkeypatch.setattr(robin, "parse_form_tokens", lambda html: {})   # token lost
    async with robin.netconfig.new_session() as s:
        out = await robin.ahmia_search(s, "janeroe")
    assert out["status"] == "error" and out["hits"] == []


@pytest.mark.asyncio
async def test_run_combines_ahmia_and_supplied_breaches(ahmia):
    verdicts = [{"identifier": "jane.roe@example.com", "breaches": [
        {"name": "Adobe", "date": "2013", "data_classes": ["Passwords"], "sources": ["XposedOrNot"]}]}]
    out = await robin.run(["janeroe", "jane.roe@example.com", "ab"], ["jane.roe@example.com"],
                          breach_verdicts=verdicts)
    assert [b["term"] for b in out["ahmia"]] == ["janeroe", "jane.roe@example.com"]  # "ab" too short
    assert out["ahmia"][1]["hits"][0]["onion"] == ONION_C
    assert out["breaches"] is verdicts
    assert out["analysis"] is None


# ── Cited-only analysis ───────────────────────────────────────────────────────

SOURCES = {"A1": {"type": "ahmia"}, "B1": {"type": "breach"}}


def test_uncited_and_fabricated_citations_are_dropped():
    raw = json.dumps({"findings": [
        {"statement": "Handle appears on a leak forum", "sources": ["A1"], "confidence": "medium"},
        {"statement": "Subject lives in Berlin", "sources": []},
        {"statement": "Subject sold drugs", "sources": ["A9"]},
        {"statement": "Email in Adobe breach", "sources": ["B1", "Z3"], "confidence": "bogus"},
    ]})
    out = robin.validate_findings("```json\n" + raw + "\n```", SOURCES)
    assert [f["statement"] for f in out["findings"]] == [
        "Handle appears on a leak forum", "Email in Adobe breach"]
    assert out["findings"][0]["confidence"] == "MEDIUM"
    assert out["findings"][1] == {"statement": "Email in Adobe breach", "sources": ["B1"],
                                  "confidence": "LOW"}
    assert out["rejected"] == 2


def test_non_json_model_output_yields_no_findings():
    out = robin.validate_findings("I think the subject is a hacker.", SOURCES)
    assert out["findings"] == [] and out["error"]


def test_sources_are_numbered_per_type():
    ahmia = [{"hits": [{"term": "t", "title": "a", "description": "", "onion": "x.onion",
                        "last_seen": ""}]}]
    verdicts = [{"identifier": "e@x.y", "breaches": [
        {"name": "Adobe", "date": "2013", "data_classes": [], "sources": ["XposedOrNot"]}]}]
    assert list(robin.build_sources(ahmia, verdicts)) == ["A1", "B1"]


@pytest.mark.asyncio
async def test_analysis_goes_through_the_shared_ai_client(monkeypatch):
    from osint.adapters import ai_verifier
    seen = {}

    async def fake_complete(provider, system, user, max_tokens=1000):
        seen["user"] = json.loads(user)
        return {"text": json.dumps({"findings": [
            {"statement": "Seen on forum", "sources": ["A1"], "confidence": "LOW"}]}),
            "model": "m"}

    monkeypatch.setattr(ai_verifier, "complete", fake_complete)
    out = await robin.analyse("claude", {"terms": ["t"]}, SOURCES)
    assert out["findings"][0]["sources"] == ["A1"] and out["model"] == "m"
    assert set(seen["user"]["sources"]) == {"A1", "B1"}
