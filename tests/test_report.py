import csv
import json
import os

import pytest

from osint.report import save_json, save_csv, save_txt


@pytest.fixture
def results():
    return [
        {"platform": "GitHub", "found": True, "url": "https://github.com/janeroe",
         "category": "dev", "confidence": "high", "source": "builtin",
         "error": None, "status_code": 200},
        {"platform": "Reddit", "found": False, "url": "https://reddit.com/u/janeroe",
         "category": "social", "confidence": "low", "source": "builtin",
         "error": None, "status_code": 404},
        {"platform": "Broken", "found": False, "url": "https://broken.example",
         "category": "other", "confidence": "low", "source": "wmn",
         "error": "timeout", "status_code": None},
    ]


def test_save_json_round_trip(tmp_path, results):
    path = save_json("janeroe", results, str(tmp_path))
    assert os.path.exists(path)

    data = json.loads(open(path, encoding="utf-8").read())
    assert data["target"] == "janeroe"
    assert data["summary"]["total_checked"] == 3
    assert data["summary"]["found"] == 1
    assert data["summary"]["errors"] == 1
    assert [f["platform"] for f in data["found"]] == ["GitHub"]


def test_save_json_includes_extra_intel(tmp_path, results):
    path = save_json("janeroe", results, str(tmp_path),
                     extra={"location": {"subject": "NZ", "conflicts": []}})
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["intel"]["location"]["subject"] == "NZ"


def test_save_csv_round_trip(tmp_path, results):
    path = save_csv("janeroe", results, str(tmp_path))
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 3
    assert rows[0]["platform"] == "GitHub"
    assert rows[0]["found"] == "True"


def test_save_csv_ignores_unknown_keys(tmp_path, results):
    results[0]["location_hints"] = ["Auckland"]
    path = save_csv("janeroe", results, str(tmp_path))
    with open(path, newline="", encoding="utf-8") as f:
        header = next(csv.reader(f))
    assert "location_hints" not in header


def test_save_txt_round_trip(tmp_path, results):
    path = save_txt("janeroe", results, str(tmp_path))
    text = open(path, encoding="utf-8").read()

    assert "janeroe" in text
    assert "Found  : 1/3" in text
    assert "https://github.com/janeroe" in text
    assert "Broken" in text  # error section


def test_reports_written_inside_requested_directory(tmp_path, results):
    for saver in (save_json, save_csv, save_txt):
        path = saver("janeroe", results, str(tmp_path))
        assert os.path.realpath(path).startswith(os.path.realpath(str(tmp_path)))


def test_identity_confidence_in_csv_and_txt(tmp_path, results):
    results[0]["identity_confidence"] = "HIGH"
    results[0]["evidence"] = ["same username", "same avatar as Twitter/X"]

    path = save_csv("janeroe", results, str(tmp_path))
    with open(path, newline="", encoding="utf-8") as f:
        row = next(csv.DictReader(f))
    assert row["identity_confidence"] == "HIGH"
    assert row["evidence"] == "same username; same avatar as Twitter/X"

    text = open(save_txt("janeroe", results, str(tmp_path)), encoding="utf-8").read()
    assert "[HIGH] GitHub" in text
    assert "evidence: same username; same avatar as Twitter/X" in text


def test_html_report_shows_identity_and_escapes_evidence(tmp_path, results):
    from osint.pdf_report import _build_html
    results[0]["identity_confidence"] = "MEDIUM"
    results[0]["evidence"] = ["names '<script>x</script>'"]
    html = _build_html("janeroe", results)
    assert ">MEDIUM<" in html
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_empty_results_do_not_crash(tmp_path):
    for saver in (save_json, save_csv, save_txt):
        assert os.path.exists(saver("nobody", [], str(tmp_path)))


def test_github_intel_is_labelled_with_the_accounts_identity():
    from osint.pdf_report import _build_html
    gh = {"emails": ["x@corp.com"], "orgs": [], "timezone": {}, "npm_packages": []}
    low = _build_html("jane", [{"platform": "GitHub", "found": True, "identity_confidence": "LOW",
                                "url": "u", "category": "dev"}], github_intel=gh)
    assert "identity LOW" in low and "may describe someone else" in low
    high = _build_html("jane", [{"platform": "GitHub", "found": True, "identity_confidence": "HIGH",
                                 "url": "u", "category": "dev"}], github_intel=gh)
    assert "identity HIGH" in high and "may describe someone else" not in high


# Investigation report: every finding survives every module combination

def _found(platform="Dev.to"):
    return {"platform": platform, "url": "https://dev.to/janeroe", "category": "dev",
            "color": "#fff", "found": True, "confidence": "high", "source": "builtin",
            "og_title": "Jane Roe", "identity_confidence": "LOW", "evidence": ["same username"]}


def test_profiles_table_survives_crt_data():
    """--crt reused the profile table's variable name and wiped every profile."""
    from osint.pdf_report import _build_html
    crt = {"all_domains": [], "email_domains": [], "named_domains": ["janeroe.dev"],
           "status": {"username": "ok", "email": "not checked: HTTP 502"}}
    html = _build_html("janeroe", [_found()], crt_data=crt)
    assert "Dev.to" in html and "https://dev.to/janeroe" in html
    assert "janeroe.dev" in html


def test_email_accounts_and_unchecked_sources_are_reported():
    from osint.pdf_report import _build_html
    emails = [
        {"platform": "office365", "url": "https://office365.com", "found": True},
        {"platform": "spotify", "url": "https://spotify.com", "found": False},
        {"platform": "amazon", "url": "https://amazon.com", "found": False,
         "error": "not checked: rate-limited or blocked"},
    ]
    html = _build_html("janeroe", [_found()], email="jane@example.com", email_results=emails,
                       wayback_data={"Dev.to": {"error": "not checked: archive.org unreachable"}},
                       paste_data={"status": {"gists": "not checked: HTTP 403"}},
                       github_intel={"error": "GitHub API rate limit"})
    assert "office365" in html and "spotify" not in html
    assert "1 of 3 sites" in html and "1 site(s) not checked" in html
    for text in ("archive.org unreachable", "HTTP 403", "GitHub API rate limit", "Not checked"):
        assert text in html


def test_report_escapes_the_email_and_username():
    from osint.pdf_report import _build_html
    html = _build_html("<b>x</b>", [], email="<script>@x.y")
    assert "<script>@x.y" not in html and "<b>x</b>" not in html


@pytest.mark.parametrize("payload", ["=HYPERLINK(\"http://evil\",\"x\")", "+1+cmd|' /C calc'!A0",
                                     "-2+3", "@SUM(A1)", "\t=1", "\r=1"])
def test_csv_cells_cannot_become_formulas(tmp_path, payload):
    r = {"platform": payload, "found": True, "url": "https://x.test", "category": "social",
         "confidence": "high", "evidence": [payload], "source": "builtin", "error": payload}
    rows = list(csv.DictReader(open(save_csv("jane", [r], str(tmp_path)), encoding="utf-8")))
    for field in ("platform", "evidence", "error"):
        assert rows[0][field].startswith("'"), (field, rows[0][field])


def test_csv_leaves_ordinary_values_alone(tmp_path):
    r = {"platform": "GitHub", "found": True, "url": "https://github.com/jane", "category": "dev",
         "confidence": "high", "evidence": ["same username"], "source": "builtin", "status_code": 200}
    row = next(csv.DictReader(open(save_csv("jane", [r], str(tmp_path)), encoding="utf-8")))
    assert row["platform"] == "GitHub" and row["status_code"] == "200"


def test_email_only_report_is_named_after_the_address(tmp_path):
    from osint.pdf_report import generate_pdf_report
    rp = generate_pdf_report(username="", results=[], output_dir=str(tmp_path),
                             email="jane.roe@example.com", email_results=[])
    name = os.path.basename(rp["html"])
    assert name.startswith("jane_roe_at_example_com_report_")
    page = open(rp["html"], encoding="utf-8").read()
    assert "Target: <span" in page and "jane.roe@example.com" in page and ">@<" not in page
