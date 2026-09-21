import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from osint import netconfig


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
