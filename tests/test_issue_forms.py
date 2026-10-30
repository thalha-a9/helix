"""Issue forms must be valid YAML, or GitHub silently drops them."""

import glob
import os

import pytest

yaml = pytest.importorskip("yaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORMS = sorted(glob.glob(os.path.join(ROOT, ".github", "ISSUE_TEMPLATE", "*.yml")))


@pytest.mark.parametrize("path", FORMS, ids=os.path.basename)
def test_issue_form_is_valid(path):
    with open(path, encoding="utf-8") as f:
        form = yaml.safe_load(f)
    if os.path.basename(path) == "config.yml":
        assert form["contact_links"]
        return
    assert form["name"] and form["description"] and form["body"]
    ids = [item["id"] for item in form["body"] if "id" in item]
    assert len(ids) == len(set(ids))
    for item in form["body"]:
        assert item["type"] in ("markdown", "input", "textarea", "dropdown", "checkboxes")


def test_there_is_a_false_positive_form():
    assert any(p.endswith("false_positive.yml") for p in FORMS)
