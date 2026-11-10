"""The Maltego transform and the SpiderFoot module report what Helix reports."""

import importlib.util
import os
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
pytestmark = pytest.mark.skipif(not os.path.isdir(os.path.join(ROOT, "integrations")),
                                reason="integrations are in the repository, not the installed package")

REPORT = {
    "summary": {"attempted": 56, "answered": 50, "found": 2, "unanswered": 6},
    "accounts": [
        {"platform": "GitHub", "url": "https://github.com/janeroe?a=1&b=<2>", "identity_confidence": "HIGH",
         "source": "builtin", "category": "dev"},
        {"platform": "Mastodon", "url": "https://mastodon.social/@janeroe", "identity_confidence": "",
         "source": "builtin", "category": "social"},
    ],
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "integrations", path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_maltego_gets_one_website_per_confirmed_account_and_the_unanswered_count():
    m = load("maltego/helix_transform.py", "helix_transform")
    root = ET.fromstring(m.message(*m.entities_for(REPORT)))          # well-formed, addresses escaped
    entities = root.findall(".//Entity")
    assert [e.find("Value").text for e in entities] == [a["url"] for a in REPORT["accounts"]]
    assert [e.find("Weight").text for e in entities] == ["100", "40"]
    assert entities[0].attrib["Type"] == "maltego.Website"
    notes = [(n.attrib["MessageType"], n.text) for n in root.findall(".//UIMessage")]
    assert notes[0] == ("Inform", "Helix: 2 account(s) confirmed on the 50 sites that answered.")
    assert notes[1][0] == "PartialError" and "6 sites gave no clear answer" in notes[1][1]


def test_maltego_without_a_username_says_so(capsys):
    m = load("maltego/helix_transform.py", "helix_transform")
    assert m.main(["helix_transform.py"]) == 1
    assert "no username given" in capsys.readouterr().out


def test_spiderfoot_events_match_its_own_account_finder():
    m = load("spiderfoot/sfp_helix.py", "sfp_helix")
    module = m.sfp_helix()
    assert module.watchedEvents() == ["USERNAME"]
    events = module.events_for(REPORT)
    assert [k for k, _ in events] == ["ACCOUNT_EXTERNAL_OWNED", "ACCOUNT_EXTERNAL_OWNED", "SOCIAL_MEDIA"]
    assert events[0][1] == "GitHub (Category: dev)\n<SFURL>https://github.com/janeroe?a=1&b=<2></SFURL>"
    assert set(k for k, _ in events) <= set(module.producedEvents())
    assert set(m.sfp_helix.opts) == set(m.sfp_helix.optdescs)
