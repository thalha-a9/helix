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
