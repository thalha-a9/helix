"""
Relationship mapping (#23), the approved-subject gate, and how breach,
dark-web and relationship findings reach every output.
"""

import csv
import json
import os

import pytest

from osint import relationships as rel
from osint.graph import generate_graph
from osint.pdf_report import _build_html
from osint.report import save_csv, save_json, save_txt
from osint.subject import approved_identifiers


def _page(desc):
    return f'<html><head><meta property="og:description" content="{desc}"></head></html>'


def _found(platform, grade, bio=""):
    return {"platform": platform, "url": f"https://{platform.lower()}.com/janeroe",
            "found": True, "identity_confidence": grade, "declared_bio": bio,
            "category": "social", "color": "#fff"}


# ── Extraction: declarations only ─────────────────────────────────────────────

@pytest.mark.parametrize("bio,expected", [
    ("Senior engineer at Google, previously Meta.",
     {("employer", "Google"), ("former_employer", "Meta")}),
    ("CEO @ Acme Corp | husband of @jane_doe",
     {("employer", "Acme Corp"), ("family", "@jane_doe")}),
    ("Works for @stripe. Views my own.", {("employer", "stripe")}),
    ("Maintainer of Django. Ex-Googler", {("organization", "Django"), ("former_employer", "Google")}),
    ("Engineer at Google working on Search", {("employer", "Google")}),
    ("Photographer. Say hi to @bob_k", {("mentioned", "@bob_k")}),
    ("Student at University of Oxford", {("education", "University of Oxford")}),
    ("PhD student at MIT and ex-Google", {("education", "MIT"), ("former_employer", "Google")}),
    ("Engineer at Bank of America. Opinions mine", {("employer", "Bank of America")}),
    ("Engineer at Google and Meta", {("employer", "Google")}),
    ("Engineer at Google for 5 years", {("employer", "Google")}),
    ("Works at The New York Times", {("employer", "New York Times")}),
])
def test_declared_relations_are_extracted(bio, expected):
    got = {(d["relation"], d["target"]) for d in rel.extract_declarations(bio, "janeroe")}
    assert got == expected


@pytest.mark.parametrize("bio", [
    "developer at night, engineer at heart",
    "Jane Roe. Loves hiking with the Roe family.",       # shared surname ≠ relationship
    "contact: jane@example.com",
    "Formerly known as JR",
    "I am @janeroe everywhere",                         # the subject herself
    "",
])
def test_nothing_is_inferred(bio):
    assert rel.extract_declarations(bio, "janeroe") == []


def test_bio_is_read_from_own_description_only():
    rs = [{"found": True, "_page_text": _page("Engineer at Google") +
           "<body>Followers: works at Microsoft</body>"},
          {"found": False, "_page_text": _page("Engineer at Oracle")}]
    rel.annotate_relations(rs)
    assert rs[0]["declared_bio"] == "Engineer at Google"
    assert "declared_bio" not in rs[1]


# ── Confidence: never stronger than the account that declared it ──────────────

def test_single_account_declaration_is_capped_by_identity():
    edges = rel.build_relationships([_found("Twitter", "LOW", "Engineer at Google")], "janeroe")
    assert [(e["target"], e["confidence"]) for e in edges] == [("Google", "LOW")]
    edges = rel.build_relationships([_found("Twitter", "HIGH", "Engineer at Google")], "janeroe")
    assert edges[0]["confidence"] == "MEDIUM"          # one declaration → at most MEDIUM


def test_two_independent_accounts_reach_high():
    results = [_found("Twitter", "HIGH", "Engineer at Google"), _found("GitHub", "MEDIUM", "")]
    gh = {"company": "@Google", "orgs": [{"name": "golang"}]}
    edges = {e["target"]: e for e in rel.build_relationships(results, "janeroe", gh)}
    assert edges["Google"]["confidence"] == "HIGH"
    assert {s["platform"] for s in edges["Google"]["sources"]} == {"Twitter", "GitHub"}
    assert edges["golang"]["relation"] == "organization"
    assert edges["golang"]["sources"][0]["method"] == "public GitHub organisation membership"


def test_github_intel_ignored_when_github_not_found():
    gh = {"company": "Google", "orgs": [{"name": "golang"}]}
    assert rel.build_relationships([_found("Twitter", "HIGH", "")], "janeroe", gh) == []


def test_org_that_is_also_employer_is_one_edge():
    results = [_found("GitHub", "HIGH", "")]
    gh = {"company": "golang", "orgs": [{"name": "golang"}]}
    edges = rel.build_relationships(results, "janeroe", gh)
    assert len(edges) == 1 and edges[0]["relation"] == "employer"


def test_unfound_profiles_contribute_nothing():
    r = _found("Twitter", "HIGH", "Engineer at Google")
    r["found"] = False
    assert rel.build_relationships([r], "janeroe") == []


# ── Approved-subject gate ─────────────────────────────────────────────────────

def test_github_emails_need_a_corroborated_account():
    gh = {"emails": ["jr@corp.com"]}
    approved, held = approved_identifiers("me@x.com", "janeroe", [_found("GitHub", "LOW")], gh)
    assert approved["emails"] == ["me@x.com"]
    assert held and "identity LOW" in held[0]
    approved, held = approved_identifiers(None, "janeroe", [_found("GitHub", "MEDIUM")], gh)
    assert approved["emails"] == ["jr@corp.com"] and held == []
    assert approved["terms"] == ["janeroe", "jr@corp.com"]


def test_real_name_needs_a_corroborated_source():
    results = [_found("Dribbble", "LOW")]
    approved, held = approved_identifiers(None, "janeroe", results, {}, "Jane Roe", "Dribbble")
    assert "Jane Roe" not in approved["terms"] and "Dribbble" in held[0]
    results = [_found("Dribbble", "HIGH")]
    approved, _ = approved_identifiers(None, "janeroe", results, {}, "Jane Roe", "Dribbble")
    assert approved["terms"] == ["janeroe", "Jane Roe"]


# ── Every writer carries the findings ─────────────────────────────────────────

EDGE = {"relation": "employer", "target": "Acme <script>x</script>", "target_type": "org",
        "confidence": "MEDIUM",
        "sources": [{"platform": "Twitter", "url": "https://twitter.com/janeroe",
                     "method": "declared in profile bio", "quote": "CEO @ Acme", "identity": "HIGH"}]}
VERDICT = {"identifier": "jane@example.com", "kind": "email", "checked_at": "2026-09-25 10:00 UTC",
           "exposed": True, "note": "",
           "sources": [{"source": "XposedOrNot", "status": "ok", "detail": "", "count": 1}],
           "breaches": [{"name": "Adobe", "date": "2013", "records": 5, "verified": True,
                         "data_classes": ["Passwords"], "domain": "", "sources": ["XposedOrNot"]}],
           "summary": "jane@example.com appears in 1 breach (2013), passwords exposed in 1 — source: XposedOrNot."}
DARK = {"ahmia": [{"term": "janeroe", "status": "ok", "detail": "", "dropped": 0, "hits": [
    {"title": "Forum <b>profile</b>", "description": "", "onion": "a" * 56 + ".onion",
     "url": "http://" + "a" * 56 + ".onion/u", "last_seen": "2024-07-03", "term": "janeroe",
     "source": "Ahmia"}]}], "breaches": [VERDICT],
    "analysis": {"findings": [{"statement": "Seen on forum", "sources": ["A1"], "confidence": "LOW"}]}}
EXTRA = {"relationships": [EDGE], "breaches": [VERDICT], "darkweb": DARK}


def test_json_csv_txt_include_intel(tmp_path):
    d = str(tmp_path)
    data = json.load(open(save_json("janeroe", [], d, extra=EXTRA)))
    assert data["intel"]["breaches"][0]["breaches"][0]["name"] == "Adobe"
    rows = list(csv.DictReader(open(save_csv("janeroe", [], d, extra=EXTRA))))
    cats = {r["category"] for r in rows}
    assert cats == {"breach", "darkweb", "relationship"}
    txt = open(save_txt("janeroe", [], d, extra=EXTRA)).read()
    assert "RELATIONSHIPS" in txt and "appears in 1 breach" in txt and "DARK-WEB LEADS" in txt
    assert "[AI LOW] Seen on forum [A1]" in txt


def test_clean_verdict_still_gets_a_csv_row(tmp_path):
    clean = {**VERDICT, "breaches": [], "exposed": False,
             "summary": "jane@example.com: no breaches found in XposedOrNot (checked t)."}
    rows = list(csv.DictReader(open(save_csv("j", [], str(tmp_path), extra={"breaches": [clean]}))))
    assert rows[0]["evidence"].startswith("jane@example.com: no breaches found")


def test_html_report_sections_are_escaped():
    html = _build_html("janeroe", [], breach_verdicts=[VERDICT], darkweb=DARK,
                       relationships=[EDGE])
    assert "Relationships (1)" in html and "Breach Exposure" in html and "Dark-Web Leads" in html
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "<b>profile</b>" not in html


def test_graph_gets_relation_breach_and_onion_nodes(tmp_path):
    out = os.path.join(tmp_path, "g.html")
    generate_graph("janeroe", [], out, email="jane@example.com",
                   relationships=[EDGE], breach_verdicts=[VERDICT], darkweb=DARK)
    page = open(out).read()
    nodes = json.loads(page.split("const NODES=")[1].split(";\n")[0])
    types = {n["type"] for n in nodes}
    assert {"relation", "breach", "onion"} <= types
    links = json.loads(page.split("const LINKS=")[1].split(";\n")[0])
    breach_id = next(n["id"] for n in nodes if n["type"] == "breach")
    email_id = next(n["id"] for n in nodes if n.get("root_type") == "email")
    assert {"source": email_id, "target": breach_id, "type": "breach"} in links
    assert "<script>x" not in page
