"""
The left-out list: people can ask that their username or email address is
never looked up with Helix. The list holds tokens, not names, and a name on
it is refused before any request is sent.
"""

import argparse
import json

import pytest

from helix_osint import cli as helix
from helix_osint import leftout
from helix_osint.leftout import is_left_out, token


def test_a_token_is_stable_and_hides_the_name():
    t = token("JaneRoe")
    assert t == token("@janeroe") == token("  janeroe ") and len(t) == 64
    assert "janeroe" not in t and t != token("janeroe2")
    assert token("Jane.Roe@Example.com") == token("jane.roe@example.com")
    # Fixed parameters: a token made today must match one made next year.
    assert (leftout.SALT, leftout.ROUNDS) == (b"helix-left-out-v1", 200_000)
    assert token("janeroe") == "1f6ef1b4d2f88c9123c1596f8ab877d5d3c8cb2b3590f09ed93a1c556fd28cce"


def test_only_listed_names_are_left_out():
    tokens = {token("janeroe")}
    assert is_left_out("JaneRoe", tokens) and is_left_out("@janeroe", tokens)
    assert not is_left_out("janeroe2", tokens) and not is_left_out("", tokens)
    assert not is_left_out("janeroe", set())


def test_the_shipped_list_is_a_valid_list_of_tokens():
    data = json.loads(leftout.SHIPPED.read_text())
    assert leftout._valid(data)
    assert not leftout._valid({"schema": leftout.SCHEMA, "tokens": ["janeroe"]})     # a name, not a token
    assert not leftout._valid({"schema": "other", "tokens": []})


def test_the_shipped_list_and_the_download_are_both_honoured(monkeypatch, tmp_path):
    shipped = tmp_path / "shipped.json"
    shipped.write_text(json.dumps({"schema": leftout.SCHEMA, "tokens": [token("alice")]}))
    monkeypatch.setattr(leftout, "SHIPPED", shipped)
    leftout._CACHE.write_text(json.dumps({"schema": leftout.SCHEMA, "tokens": [token("bob").upper()]}))
    assert is_left_out("alice") and is_left_out("bob") and not is_left_out("carol")
    leftout._CACHE.write_text("not json")
    assert is_left_out("alice") and not is_left_out("bob")


def _args(**kw):
    base = dict(username="janeroe", email=None, providers=False, ai=None,
                all_sources=False, wmn=False, sherlock=False, maigret=False,
                maigret_engine=False, maigret_timeout=30, maigret_top=10, wmn_timeout=30,
                sherlock_timeout=30, no_control=False, wayback=False, crt=False, paste=False,
                breach=False, darkweb=False, holehe=False, pivot=False, pivot_depth=1,
                phash=False, permutations=False, location=None, format="json", report=False,
                email_permute=False, output=None, no_browser=True, nsfw=False,
                proxy=None, tor=False)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def listed(monkeypatch, tmp_path):
    shipped = tmp_path / "shipped.json"
    shipped.write_text(json.dumps({"schema": leftout.SCHEMA,
                                   "tokens": [token("janeroe"), token("jane@example.com")]}))
    monkeypatch.setattr(leftout, "SHIPPED", shipped)
    monkeypatch.chdir(tmp_path)

    async def must_not_scan(*a, **kw):
        raise AssertionError("a left-out name was scanned")
    monkeypatch.setattr(helix, "check_username", must_not_scan)
    monkeypatch.setattr(helix, "check_email", must_not_scan)


@pytest.mark.asyncio
@pytest.mark.parametrize("kw,shown", [
    ({"username": "JaneRoe"}, "JaneRoe is on the left-out list"),
    ({"username": "someoneelse", "email": "Jane@Example.com"}, "Jane@Example.com is on the left-out list"),
    ({"username": "janeroe", "no_control": True, "include_off": True}, "janeroe is on the left-out list"),
])
async def test_a_left_out_name_is_refused_before_any_request(listed, capsys, kw, shown):
    with pytest.raises(SystemExit) as stop:
        await helix.run(_args(**kw))
    assert stop.value.code == 3
    out = capsys.readouterr().out
    assert shown in out and "Nothing was requested." in out and "docs/LEFT_OUT.md" in out


@pytest.mark.asyncio
async def test_pivot_does_not_follow_a_left_out_alias(listed, monkeypatch):
    from helix_osint import pivot
    scanned = []

    async def fake_check(username, platforms=None, concurrency=None):
        scanned.append(username)
        return []
    import helix_osint.checker as ck
    monkeypatch.setattr(ck, "check_username", fake_check)
    initial = [{"platform": "GitHub", "found": True,
                "bio_links": {"twitter": "janeroe", "instagram": "otherhandle"}}]
    await pivot.pivot_scan("rootname", initial, {}, 1)
    assert scanned == ["otherhandle"]


def test_the_request_form_asks_for_a_token_never_a_name():
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".github", "ISSUE_TEMPLATE", "left_out.yml")
    if not os.path.exists(path):
        pytest.skip("repository files, not in the source package")
    form = open(path, encoding="utf-8").read()
    assert "Do not write your username or address here" in form and "--left-out-token" in form
