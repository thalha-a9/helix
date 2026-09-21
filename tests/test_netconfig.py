import os

import aiohttp
import pytest

from osint import netconfig


def test_no_proxy_by_default():
    assert netconfig.get_proxy() is None
    assert netconfig.request_kwargs() == {}
    assert netconfig.curl_kwargs() == {}
    assert "DIRECT" in netconfig.describe()


def test_http_proxy_is_passed_per_request():
    netconfig.set_proxy("http://10.0.0.5:3128")
    assert netconfig.request_kwargs() == {"proxy": "http://10.0.0.5:3128"}
    assert netconfig.curl_kwargs()["proxies"]["https"] == "http://10.0.0.5:3128"


def test_http_proxy_exported_to_env_for_third_party_sessions():
    netconfig.set_proxy("http://10.0.0.5:3128")
    assert os.environ["HTTPS_PROXY"] == "http://10.0.0.5:3128"
    assert os.environ["http_proxy"] == "http://10.0.0.5:3128"


@pytest.mark.skipif(not netconfig.HAS_SOCKS, reason="aiohttp-socks not installed")
@pytest.mark.asyncio
async def test_socks_proxy_applies_at_connector_not_per_request():
    netconfig.set_proxy("socks5://127.0.0.1:9050")
    assert netconfig.is_socks()
    # SOCKS cannot ride a per-request kwarg — it must come from the connector.
    assert netconfig.request_kwargs() == {}
    connector = netconfig.build_connector()
    try:
        assert type(connector) is not aiohttp.TCPConnector
    finally:
        await connector.close()


@pytest.mark.skipif(not netconfig.HAS_SOCKS, reason="aiohttp-socks not installed")
def test_socks_proxy_not_leaked_into_env():
    netconfig.set_proxy("socks5://127.0.0.1:9050")
    # aiohttp cannot honour socks:// from env; exporting it would silently
    # produce direct connections instead of failing loudly.
    assert "HTTPS_PROXY" not in os.environ


@pytest.mark.asyncio
async def test_plain_connector_when_no_proxy():
    connector = netconfig.build_connector(limit=5)
    try:
        assert type(connector) is aiohttp.TCPConnector
    finally:
        await connector.close()


@pytest.mark.parametrize("bad", [
    "ftp://1.2.3.4:21",
    "gopher://example.com",
    "http://",
    "not-a-url",
])
def test_invalid_proxy_rejected(bad):
    with pytest.raises(ValueError):
        netconfig.set_proxy(bad)
    assert netconfig.get_proxy() is None


@pytest.mark.parametrize("good", [
    "http://10.0.0.5:3128",
    "https://proxy.example.com:8443",
    "http://user:pass@10.0.0.5:3128",
])
def test_valid_http_proxies_accepted(good):
    assert netconfig.set_proxy(good) == good


def test_clearing_proxy():
    netconfig.set_proxy("http://10.0.0.5:3128")
    netconfig.set_proxy(None)
    assert netconfig.get_proxy() is None
    assert netconfig.request_kwargs() == {}


def test_credentials_redacted():
    netconfig.set_proxy("http://alice:hunter2@10.0.0.5:3128")
    described = netconfig.describe()
    assert "hunter2" not in described
    assert "alice" not in described
    assert "10.0.0.5:3128" in described


def test_redact_leaves_credential_free_urls_intact():
    assert netconfig.redact("socks5://127.0.0.1:9050") == "socks5://127.0.0.1:9050"
    assert netconfig.redact(None) == ""


def test_describe_reports_env_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.9:8080")
    assert "10.0.0.9:8080" in netconfig.describe()


@pytest.mark.asyncio
async def test_new_session_trusts_env():
    session = netconfig.new_session()
    try:
        assert session.trust_env is True
    finally:
        await session.close()


def test_tor_shorthand_is_a_socks_url():
    assert netconfig.is_socks(netconfig.TOR_PROXY)
    assert netconfig.TOR_PROXY.endswith(":9050")
