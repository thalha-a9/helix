"""--nsfw must actually change what is scanned, for every database.

Before 3.5.0 none of these filters fired: WhatsMyName's field is "cat" with
"xx NSFW xx" (the filter read "category" == "adult"), and the Sherlock and
Maigret caches dropped the adult flag, so adult sites were always scanned.
"""

import asyncio

import pytest

from helix_osint.adapters import maigret_adapter, sherlock_adapter, wmn_adapter


# WhatsMyName

@pytest.mark.parametrize("site,nsfw", [
    ({"cat": "xx NSFW xx"}, True),
    ({"cat": "XX NSFW XX "}, True),
    ({"category": "adult"}, True),        # older schema
    ({"cat": "dating"}, False),
    ({"cat": "social"}, False),
    ({}, False),
])
def test_wmn_nsfw_detection(site, nsfw):
    assert wmn_adapter.is_nsfw(site) is nsfw


def test_wmn_category_comes_from_the_cat_field():
    assert wmn_adapter.site_category({"cat": "Social"}) == "social"
    assert wmn_adapter.site_category({"category": "gaming"}) == "gaming"


def _wmn_payload():
    return {"sites": [
        {"name": "Safe", "uri_check": "https://safe.example/u/{account}", "e_code": 200,
         "e_string": "profile", "m_string": "not found", "m_code": 404, "cat": "social"},
        {"name": "Adult", "uri_check": "https://adult.example/u/{account}", "e_code": 200,
         "e_string": "profile", "m_string": "not found", "m_code": 404, "cat": "xx NSFW xx"},
    ]}


class _FakeResp:
    status = 200

    def __init__(self, payload):
        self._payload = payload

    async def json(self, content_type=None):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    def __init__(self, payload):
        self._payload = payload

    def get(self, *a, **kw):
        return _FakeResp(self._payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def test_wmn_fetch_drops_adult_sites_unless_asked(monkeypatch):
    monkeypatch.setattr(wmn_adapter.netconfig, "new_session", lambda **kw: _FakeSession(_wmn_payload()))
    safe = asyncio.run(wmn_adapter.fetch_wmn_platforms(include_nsfw=False))
    allp = asyncio.run(wmn_adapter.fetch_wmn_platforms(include_nsfw=True))
    assert "Safe" in safe and "Adult" not in safe
    assert {"Safe", "Adult"} <= set(allp)
    assert safe["Safe"]["category"] == "social"


# Sherlock

def test_sherlock_keeps_the_isnsfw_flag_and_filters_on_it(monkeypatch, tmp_path):
    payload = {
        "Safe":  {"url": "https://safe.example/{}", "errorType": "status_code"},
        "Adult": {"url": "https://adult.example/{}", "errorType": "status_code", "isNSFW": True},
    }
    monkeypatch.setattr(sherlock_adapter, "_CACHE_FILE", tmp_path / "s.json")
    monkeypatch.setattr(sherlock_adapter, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(sherlock_adapter.netconfig, "new_session", lambda **kw: _FakeSession(payload))

    allp = asyncio.run(sherlock_adapter.fetch_sherlock_platforms())
    assert allp["Adult"].get("nsfw") is True and not allp["Safe"].get("nsfw")
    # The cache keeps the flag, so a cached load filters too.
    safe = asyncio.run(sherlock_adapter.load_with_fallback(include_nsfw=False))
    assert set(safe) == {"Safe"}
    assert set(asyncio.run(sherlock_adapter.load_with_fallback(include_nsfw=True))) == {"Safe", "Adult"}


# Maigret

@pytest.mark.parametrize("info,nsfw", [
    ({"tags": ["porn", "us"]}, True),
    ({"tags": ["erotic"]}, True),
    ({"tags": ["webcam"]}, True),
    ({"tags": "porn"}, True),
    ({"isNSFW": True}, True),
    ({"tags": ["dating"]}, False),
    ({"tags": ["social", "us"]}, False),
    ({}, False),
])
def test_maigret_nsfw_detection(info, nsfw):
    assert maigret_adapter.is_nsfw(info) is nsfw


def test_maigret_fetch_flags_and_load_filters(monkeypatch, tmp_path):
    payload = {"sites": {
        "Safe":  {"url": "https://safe.example/{username}", "tags": ["social"],
                  "absenceStrs": ["not found"]},
        "Adult": {"url": "https://adult.example/{username}", "tags": ["porn"],
                  "absenceStrs": ["not found"]},
    }}
    monkeypatch.setattr(maigret_adapter, "_CACHE_FILE", tmp_path / "m.json")
    monkeypatch.setattr(maigret_adapter, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(maigret_adapter.netconfig, "new_session", lambda **kw: _FakeSession(payload))

    allp = asyncio.run(maigret_adapter.fetch_maigret_platforms())
    assert allp["Adult"].get("nsfw") is True
    assert set(asyncio.run(maigret_adapter.load_with_fallback(include_nsfw=False))) == {"Safe"}
    assert set(asyncio.run(maigret_adapter.load_with_fallback(include_nsfw=True))) == {"Safe", "Adult"}


def test_cache_files_were_renamed_so_flagless_caches_are_not_reused():
    assert sherlock_adapter._CACHE_FILE.name == "sherlock_data_v4.json"  # v4: probe address, all texts
    assert maigret_adapter._CACHE_FILE.name == "maigret_data_v5.json"  # v5: engine addresses


def test_wmn_shows_the_profile_page_and_probes_the_api(monkeypatch):
    payload = {"sites": [
        {"name": "dev.to", "uri_check": "https://dev.to/api/users/by_username?url={account}",
         "uri_pretty": "https://dev.to/{account}", "e_code": 200, "e_string": "\"username\"",
         "m_string": "Not Found", "m_code": 404, "cat": "coding"},
        {"name": "Plain", "uri_check": "https://plain.example/{account}", "e_code": 200,
         "e_string": "profile", "m_string": "not found", "m_code": 404, "cat": "social"},
    ]}
    monkeypatch.setattr(wmn_adapter.netconfig, "new_session", lambda **kw: _FakeSession(payload))
    p = asyncio.run(wmn_adapter.fetch_wmn_platforms())
    assert p["dev.to"]["url"] == "https://dev.to/{username}"
    assert p["dev.to"]["check_url"] == "https://dev.to/api/users/by_username?url={username}"
    assert "check_url" not in p["Plain"] and p["Plain"]["url"] == "https://plain.example/{username}"


# What the databases know beyond the address

def test_sherlock_probe_address_every_not_found_text_headers_and_known_account(monkeypatch, tmp_path):
    payload = {
        "Api": {"url": "https://api.example/{}", "urlProbe": "https://api.example/lookup/{}.json",
                "errorType": "message", "errorMsg": ["no such account", "temporarily offline"],
                "headers": {"Accept": "application/json"}, "username_claimed": "blue"},
        "One": {"url": "https://one.example/{}", "errorType": "message", "errorMsg": "gone"},
        "Posted": {"url": "https://posted.example/{}", "errorType": "status_code",
                   "request_method": "POST", "request_payload": {"name": "{}"}},
        "Injected": {"url": "https://inj.example/{}", "errorType": "status_code",
                     "headers": {"X": "1\r\nHost: evil.example"}, "username_claimed": "not a name"},
    }
    monkeypatch.setattr(sherlock_adapter, "_CACHE_FILE", tmp_path / "s.json")
    monkeypatch.setattr(sherlock_adapter, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(sherlock_adapter.netconfig, "new_session", lambda **kw: _FakeSession(payload))
    p = asyncio.run(sherlock_adapter.fetch_sherlock_platforms())
    assert p["Api"]["url"] == "https://api.example/{username}"
    assert p["Api"]["check_url"] == "https://api.example/lookup/{username}.json"
    assert p["Api"]["not_found_texts"] == ["no such account", "temporarily offline"]
    assert p["Api"]["headers"] == {"Accept": "application/json"} and p["Api"]["known"] == "blue"
    assert p["One"]["not_found_text"] == "gone" and "not_found_texts" not in p["One"]
    assert "Posted" not in p                     # a POST lookup is not asked with a GET
    assert "headers" not in p["Injected"] and "known" not in p["Injected"]


def test_wmn_skips_posted_lookups_and_carries_headers_and_a_known_account(monkeypatch):
    payload = {"sites": [
        {"name": "Posted", "uri_check": "https://posted.example/api", "post_body": "user={account}",
         "e_code": 200, "e_string": "ok", "m_string": "", "m_code": 404, "cat": "social",
         "known": ["a"]},
        {"name": "PostedInUrl", "uri_check": "https://p2.example/{account}", "post_body": "x=1",
         "e_code": 200, "e_string": "ok", "m_string": "no", "m_code": 404, "cat": "social"},
        {"name": "Api", "uri_check": "https://api.example/u/{account}", "e_code": 200,
         "e_string": "profile", "m_string": "not found", "m_code": 404, "cat": "social",
         "headers": {"Accept": "application/json"}, "known": ["john", "jane"]},
    ]}
    monkeypatch.setattr(wmn_adapter.netconfig, "new_session", lambda **kw: _FakeSession(payload))
    p = asyncio.run(wmn_adapter.fetch_wmn_platforms())
    assert "Posted" not in p and "PostedInUrl" not in p
    assert p["Api"]["headers"] == {"Accept": "application/json"} and p["Api"]["known"] == "john"
    assert p["__wmn_filter_stats__"]["posted"] == 1
