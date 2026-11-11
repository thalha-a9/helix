"""A site that was not reached is not a site without an account: the scan says so."""

from helix_osint import cli as helix


def _r(found=False, error=None, status=None):
    return {"platform": "x", "found": found, "error": error, "status_code": status}


def test_nothing_checked_is_said_plainly(capsys):
    results = [_r(error="unexpected: General SOCKS server failure")] * 5 + [_r(error="timeout")]
    line = helix.unanswered_line(results)
    assert line.startswith("No site gave a clear answer (5 proxy or Tor could not connect, 1 timeout)")
    assert "nothing was checked" in line
    helix._print_found([], results=results)
    out = capsys.readouterr().out
    assert "Nothing was checked" in out and "None found" not in out


def test_partial_answers_are_counted(capsys):
    results = [_r(status=404)] * 8 + [_r(error="timeout")] * 2
    assert helix.unanswered_line(results) == (
        "2 of 10 sites gave no clear answer (2 timeout); an account there would not be found.")
    helix._print_found([], results=results)
    assert "None found among the 8 sites that answered." in capsys.readouterr().out


def test_a_clean_scan_adds_no_warning():
    assert helix.unanswered_line([_r(status=404)] * 3) == ""


def test_a_profile_address_already_listed_is_not_added_again(capsys):
    pm = {"Dev.to": {"url": "https://dev.to/{username}", "method": "status_code", "found": [200],
                     "category": "dev", "color": "#000"}}
    loaded = {"DEV Community": {"url": "https://www.dev.to/{username}/", "method": "status_code",
                                "found": [200], "category": "dev", "color": "#000"},
              "Other": {"url": "https://other.example/{username}", "method": "status_code",
                        "found": [200], "category": "dev", "color": "#000"}}
    helix._merge_source(pm, "Sherlock", loaded)
    assert set(pm) == {"Dev.to", "Other"}               # the built-in entry is kept
    assert "1 already listed" in capsys.readouterr().out


def test_profile_key_ignores_scheme_www_and_trailing_slash():
    assert helix.profile_key("https://www.X.com/{username}/") == helix.profile_key("http://x.com/{username}")
    assert helix.profile_key("https://x.com/{username}") != helix.profile_key("https://x.com/@{username}")
