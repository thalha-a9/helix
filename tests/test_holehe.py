"""holehe adapter: real module loading, OPSEC defaults, honest failures."""

import pytest

from osint import netconfig
from osint.adapters import holehe_adapter as ha

holehe = pytest.importorskip("holehe")


def test_modules_load_despite_the_osint_name_collision():
    """holehe has a sub-package named "osint"; its own importer picked up Helix's."""
    mods = ha._holehe_modules()
    assert any(n.startswith("holehe.modules.") and n.count(".") >= 3 for n in mods)


def test_password_recovery_modules_are_off_by_default():
    from types import SimpleNamespace
    from holehe.core import get_functions
    off = {f.__name__ for f in get_functions(ha._holehe_modules(), SimpleNamespace(nopasswordrecovery=True))}
    assert not off & {"adobe", "mail_ru", "odnoklassniki", "samsung"}


@pytest.mark.parametrize("entry,found,error", [
    ({"name": "twitter", "domain": "twitter.com", "exists": True, "rateLimit": False}, True, None),
    ({"name": "twitter", "domain": "twitter.com", "exists": False, "rateLimit": False}, False, None),
    ({"name": "twitter", "domain": "twitter.com", "exists": False, "rateLimit": True}, False,
     "not checked: rate-limited or blocked"),
])
def test_result_mapping(entry, found, error):
    r = ha.to_result(entry)
    assert (r["found"], r["error"], r["url"]) == (found, error, "https://twitter.com")


def test_socks_without_httpx_socks_refuses_instead_of_going_direct(monkeypatch):
    import builtins
    real = builtins.__import__

    def no_socksio(name, *a, **kw):
        if name == "socksio":
            raise ImportError
        return real(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", no_socksio)
    netconfig.set_proxy("socks5://127.0.0.1:9050")
    with pytest.raises(RuntimeError, match="httpx"):
        ha._proxy_url()


def test_http_proxy_is_passed_through():
    netconfig.set_proxy("http://10.0.0.5:3128")
    assert ha._proxy_url() == "http://10.0.0.5:3128"


def test_adult_site_modules_are_skipped_unless_nsfw():
    default = ha._holehe_modules()
    with_nsfw = ha._holehe_modules(include_nsfw=True)
    adult = {n for n in with_nsfw if ".porn." in n}
    assert adult, "holehe should ship adult-site modules"
    assert not adult & set(default)
    assert set(default) | adult == set(with_nsfw)


@pytest.mark.parametrize("name,nsfw", [
    ("holehe.modules.porn.xvideos", True),
    ("holehe.modules.porn.pornhub", True),
    ("holehe.modules.software.office365", False),
    ("holehe.modules.social_media.porn_lookalike", False),
])
def test_nsfw_detection_uses_the_package_not_the_name(name, nsfw):
    assert ha._is_nsfw(name) is nsfw
