"""Release hygiene: one version everywhere, a safe --output, both commands."""

import os
import re
import sys

import pytest

import helix
from osint.termsafe import TerminalSafe
from osint import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_is_single_sourced():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        pyproject = f.read()
    assert 'dynamic = ["version"]' in pyproject
    assert 'version = {attr = "osint.__version__"}' in pyproject
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
    assert f"v{__version__}" in helix.BANNER


def test_readme_badge_matches_version():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        assert f"Version-{__version__}-" in f.read()


def test_changelog_has_an_entry_for_this_version():
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
        assert f"## v{__version__}" in f.read()


@pytest.mark.parametrize("target,ok", [
    ("results/jack", True),
    (".", True),
    ("../elsewhere", False),
    ("/etc", False),
])
def test_output_must_stay_inside_cwd(tmp_path, monkeypatch, target, ok):
    work = tmp_path / "helix"
    work.mkdir()
    monkeypatch.chdir(work)
    assert helix.output_within_cwd(target) is ok


def test_sibling_directory_sharing_a_prefix_is_rejected(tmp_path, monkeypatch):
    """/x/helix-evil starts with the string /x/helix but is not inside it."""
    work = tmp_path / "helix"
    work.mkdir()
    (tmp_path / "helix-evil").mkdir()
    monkeypatch.chdir(work)
    assert helix.output_within_cwd(str(tmp_path / "helix-evil")) is False
    assert helix.output_within_cwd("../helix-evil") is False


@pytest.mark.parametrize("argv0,expected", [
    ("/usr/bin/helix-osint", "helix-osint"),
    ("/usr/local/bin/helix", "helix"),
    ("helix.py", "helix"),
    ("", "helix"),
])
def test_help_names_the_command_that_was_typed(monkeypatch, argv0, expected):
    monkeypatch.setattr(sys, "argv", [argv0])
    assert helix._prog_name() == expected


def test_a_scan_that_reached_almost_nothing_says_so():
    dead = [{"platform": f"S{i}", "found": False, "error": "connection_error"} for i in range(9)]
    ok = [{"platform": "A", "found": False, "error": None}]
    assert "could not be reached" in helix.scan_health_warning(dead + ok)
    assert helix.scan_health_warning(ok * 9 + dead[:1]) == ""
    assert helix.scan_health_warning([]) == ""


@pytest.mark.parametrize("payload", [
    "\x1b]0;pwned\x07",          # retitle the terminal
    "\x1b[2J\x1b[H",             # clear the screen
    "\x1b[8m",                   # hide what follows
    "\x1b[1A\x1b[K",             # move up, erase the warning line
    "\x9b2J",                    # C1 CSI
    "\x00\x07\x08\x7f",
])
def test_scanned_text_cannot_drive_the_terminal(payload):
    import io
    buf = io.StringIO()
    out = TerminalSafe(buf)
    out.write(f"bio: {payload}hello\n")
    written = buf.getvalue()
    assert "hello\n" in written
    for ch in ("\x1b", "\x07", "\x9b", "\x00", "\x08", "\x7f"):
        assert ch not in written


def test_helix_own_colours_and_progress_survive():
    import io
    buf = io.StringIO()
    out = TerminalSafe(buf)
    text = f"\r  {helix.G}##{helix.DIM}..{helix.RST} {helix.B}{helix.R}x{helix.RST}\n\ttab"
    out.write(text)
    assert buf.getvalue() == text
