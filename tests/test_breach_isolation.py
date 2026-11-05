"""
--breach (XposedOrNot, HIBP, LeakCheck) runs after the accounts are found,
checked against made-up names and graded. It must never change them: the
same scan with and without it reports the same accounts, grades and evidence.
"""

import glob
import json
import os

import pytest

import helix

from test_breachdb import api                     # noqa: F401  (fixture)
from test_cli_intel import _args, site            # noqa: F401  (fixture)


def _accounts(tmp_path, sub):
    path = glob.glob(os.path.join(tmp_path, sub, "results", "janeroe", "janeroe_2*.json"))[0]
    data = json.load(open(path))
    return [{k: r.get(k) for k in ("platform", "url", "found", "identity_confidence", "evidence")}
            for r in data["found"]], data["summary"]


@pytest.mark.asyncio
async def test_breach_lookups_never_change_the_accounts(site, api, monkeypatch, tmp_path):
    monkeypatch.setenv("HIBP_API_KEY", "good-key")
    monkeypatch.setattr(helix, "PLATFORMS", {"Exampleweb": {
        "url": site + "/u/{username}", "method": "status_code", "found": [200],
        "category": "social", "color": "#fff"}})

    async def no_email_scan(email):
        return []
    monkeypatch.setattr(helix, "check_email", no_email_scan)

    runs = {}
    for sub, breach in (("off", False), ("on", True)):
        os.makedirs(tmp_path / sub)
        monkeypatch.chdir(tmp_path / sub)
        await helix.run(_args(tmp_path, breach=breach, darkweb=False, report=False,
                              no_control=False, location="Germany"))
        runs[sub] = _accounts(tmp_path, sub)

    assert runs["on"] == runs["off"]
    assert runs["on"][0] and runs["on"][0][0]["found"] is True
