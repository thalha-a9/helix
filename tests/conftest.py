import asyncio
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from osint import netconfig


# Fallback for environments without pytest-asyncio (e.g. system Python on Kali,
# where PEP 668 blocks pip): run coroutine tests directly instead of failing them.
def pytest_configure(config):
    if not config.pluginmanager.hasplugin("asyncio"):
        config.addinivalue_line("markers", "asyncio: coroutine test (built-in fallback runner)")


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    if pyfuncitem.config.pluginmanager.hasplugin("asyncio"):
        return None
    if not inspect.iscoroutinefunction(pyfuncitem.obj):
        return None
    kwargs = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
    asyncio.run(pyfuncitem.obj(**kwargs))
    return True


@pytest.fixture(autouse=True)
def clean_proxy_env(monkeypatch):
    """Proxy state is process-global — isolate every test from it."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    netconfig.set_proxy(None)
    yield
    netconfig.set_proxy(None)


@pytest.fixture
def profile_html():
    """A realistic found-profile page."""
    return (
        '<html><head>'
        '<meta property="og:title" content="Jane Roe (@janeroe)">'
        '<meta property="og:description" content="Photographer">'
        '<meta property="og:image" content="https://cdn.example.com/a.jpg">'
        '</head><body><a href="https://github.com/janeroe">gh</a></body></html>'
    )


@pytest.fixture
def base_result():
    return {
        "platform": "Example", "url": "https://example.com/u",
        "category": "social", "color": "#fff", "found": False,
        "error": None, "confidence": "low", "bio_links": {},
        "target_type": "username", "source": "builtin",
        "status_code": None, "og_title": "",
    }
