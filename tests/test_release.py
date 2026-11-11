"""Release hygiene: one version everywhere, a safe --output, both commands."""

import os
import re
import sys

import pytest

from helix_osint import cli as helix
from helix_osint.termsafe import TerminalSafe
from helix_osint import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_is_single_sourced():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        pyproject = f.read()
    assert 'dynamic = ["version"]' in pyproject
    assert 'version = {attr = "helix_osint.__version__"}' in pyproject
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


# One package, one name

def test_only_helix_osint_is_installed():
    """A wheel that drops `osint/` or `helix.py` at the top of site-packages
    can overwrite another project's files (PyPI has an `osint` project).
    Found by the BlackArch review of 4.0.0."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "pyproject.toml")
    if not os.path.exists(path):
        pytest.skip("pyproject.toml is not part of the installed package")
    text = open(path, encoding="utf-8").read()
    assert "py-modules" not in text
    assert 'include = ["helix_osint*"]' in text
    assert 'helix-osint = "helix_osint.cli:main"' in text and 'helix       = "helix_osint.cli:main"' in text
    # The repository keeps one file at the old path (see the next test); it is
    # not a package and nothing installs it.
    old = os.path.join(root, "osint")
    assert [os.path.relpath(os.path.join(d, f), old) for d, _, fs in os.walk(old) for f in fs
            if "__pycache__" not in d] == [os.path.join("data", "left_out.json")]
    manifest = open(os.path.join(root, "MANIFEST.in"), encoding="utf-8").read()
    assert "osint" not in manifest.replace("helix_osint", "")


def test_the_left_out_list_at_the_old_address_is_the_same_list():
    """Helix 4.0.0 fetches the day's left-out list from osint/data/ in the
    repository. That copy stays, byte for byte the same as the real list, so
    a person added to the list is also left out by 4.0.0 installs."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    old = os.path.join(root, "osint", "data", "left_out.json")
    new = os.path.join(root, "helix_osint", "data", "left_out.json")
    if not os.path.exists(old):
        pytest.skip("the old-address copy is in the repository, not in the installed package")
    assert open(old, "rb").read() == open(new, "rb").read(), \
        "copy helix_osint/data/left_out.json over osint/data/left_out.json"


def test_python_dash_m_runs_the_program():
    import subprocess
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run([sys.executable, "-m", "helix_osint", "--version"], capture_output=True, text=True, cwd=root)
    assert out.returncode == 0 and out.stdout.strip() == f"Helix v{helix.__version__}"
