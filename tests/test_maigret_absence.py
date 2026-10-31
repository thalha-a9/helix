"""Maigret entries: every absence string counts, and id-only sites are skipped."""

import asyncio

from osint import checker
from osint.adapters import maigret_adapter

# Olx.pl as Maigret lists it. Its user pages are keyed by seller ids, and some
# random strings get a generic 200 page that has the second absence string.
OLX = {
    "checkType": "message",
    "absenceStrs": ["Przepraszamy, ale nie możemy znaleźć takiej strony...", "Nie znaleziono"],
    "presenseStrs": ["Obserwuj wyszukiwanie"],
    "url": "https://www.olx.pl/oferty/uzytkownik/{username}/",
    "usernameClaimed": "test",
    "usernameUnclaimed": "noonewouldeverusethis7",
    "tags": ["business", "classified", "pl", "social"],
}
NAME = "xk7q93mzvb1tq"
GENERIC = (f'<link rel="canonical" href="https://www.olx.pl/oferty/uzytkownik/{NAME}/">'
           "<p>Nie znaleziono</p><button>Obserwuj wyszukiwanie</button>")


def _apply(pdef, status, text, username=NAME):
    result = {}
    asyncio.run(checker._apply(result, pdef, username, status, text, "", ""))
    return result


def test_every_absence_string_is_kept():
    pdef = maigret_adapter._translate("Olx.pl", OLX)
    assert pdef["method"] == "text_not_present"
    assert pdef["not_found_texts"] == OLX["absenceStrs"]
    assert pdef["not_found_text"] == OLX["absenceStrs"][0]


def test_olx_generic_page_is_not_an_account():
    pdef = maigret_adapter._translate("Olx.pl", OLX)
    assert not _apply(pdef, 200, GENERIC)["found"]
    # Reading only the first absence string, as before, let it through.
    first_only = {k: v for k, v in pdef.items() if k != "not_found_texts"}
    assert _apply(first_only, 200, GENERIC)["found"]


def test_page_without_any_absence_string_is_found():
    pdef = maigret_adapter._translate("Olx.pl", OLX)
    assert _apply(pdef, 200, f"<h1>{NAME}</h1><p>Ogłoszenia</p>")["found"]


def test_single_string_absence_is_accepted():
    pdef = maigret_adapter._translate("X", {"url": "https://x.test/{username}", "absenceStrs": "Not found"})
    assert pdef["not_found_texts"] == ["Not found"]


def test_id_only_entries_are_skipped():
    vk = {"type": "vk_id", "url": "https://vk.com/id{username}", "checkType": "status_code"}
    assert maigret_adapter._translate("VK (by id)", vk) is None
    assert maigret_adapter._translate("Olx.pl", dict(OLX, type="username")) is not None
