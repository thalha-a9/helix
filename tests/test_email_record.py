"""--record-attempt seals an email scan too, in its own record."""

import json
import os
import re

import pytest

import helix
from osint import evidence

from test_cli_intel import _args, site          # noqa: F401  (fixture)

ADDRESS = "jane.roe@example.com"
EMAIL_RESULTS = [
    {"platform": "Gravatar", "url": "https://en.gravatar.com/abc", "category": "other",
     "color": "#1E8CBE", "found": True, "error": None, "confidence": "high", "bio_links": {},
     "target_type": "email", "source": "builtin"},
    {"platform": "Spotify", "url": "https://spotify.com", "category": "other",
     "color": "#fff", "found": False, "error": "not checked: HTTP 429", "confidence": "high",
     "bio_links": {}, "target_type": "email", "source": "holehe"},
]


@pytest.fixture
def fake_email_scan(monkeypatch):
    async def scan(email, progress_cb=None):
        return [dict(r) for r in EMAIL_RESULTS]
    monkeypatch.setattr(helix, "check_email", scan)


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.asyncio
async def test_email_only_scan_is_sealed(fake_email_scan, monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    await helix.run(_args(tmp_path, username=None, email=ADDRESS, breach=False,
                          darkweb=False, report=False, record_attempt=True))
    out = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)

    label = "jane_roe_at_example_com"
    res = os.path.join(tmp_path, "results", label)
    ev_path = os.path.join(res, f"{label}_evidence.json")
    sites_path = os.path.join(res, f"{label}_sites.json")
    ev = _load(ev_path)

    assert ev["attempt"]["username"] == ADDRESS
    assert ev["attempt"]["target_type"] == "email"
    assert ev["summary"]["attempted"] == 2 and ev["summary"]["found"] == 1
    assert ev["summary"]["unanswered"] == 1
    assert ev["found"] == [{"platform": "Gravatar", "url": "https://en.gravatar.com/abc",
                            "source": "builtin"}]
    assert evidence.verify(ev, _load(sites_path)) == []

    assert f"RECORD ATTEMPT | Helix {helix.__version__} | {ADDRESS}" in out
    assert "1 site with an account for this address" in out
    assert "impossible usernames" not in out     # no control probe ran for the email
    assert ev["fingerprint"] in out


@pytest.mark.asyncio
async def test_username_and_email_get_separate_records(site, fake_email_scan, monkeypatch,
                                                       tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(helix, "PLATFORMS", {"Exampleweb": {
        "url": site + "/u/{username}", "method": "status_code", "found": [200],
        "category": "social", "color": "#fff"}})
    await helix.run(_args(tmp_path, email=ADDRESS, breach=False, darkweb=False,
                          report=False, record_attempt=True))
    out = capsys.readouterr().out

    res = os.path.join(tmp_path, "results", "janeroe")
    user_ev = _load(os.path.join(res, "janeroe_evidence.json"))
    mail_ev = _load(os.path.join(res, "janeroe_email_evidence.json"))

    assert user_ev["attempt"]["username"] == "janeroe"
    assert "target_type" not in user_ev["attempt"]       # username records unchanged
    assert user_ev["summary"]["found"] == 1
    assert mail_ev["attempt"]["username"] == ADDRESS
    assert mail_ev["attempt"]["target_type"] == "email"
    assert evidence.verify(mail_ev, _load(os.path.join(res, "janeroe_email_sites.json"))) == []
    assert out.count("RECORD ATTEMPT") == 2


@pytest.mark.asyncio
async def test_no_record_without_the_flag(fake_email_scan, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    await helix.run(_args(tmp_path, username=None, email=ADDRESS, breach=False,
                          darkweb=False, report=False, record_attempt=False))
    res = os.path.join(tmp_path, "results", "jane_roe_at_example_com")
    assert not any(f.endswith("_evidence.json") for f in os.listdir(res))
