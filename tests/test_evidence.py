"""Record-attempt evidence: honest counts, a stable fingerprint, tamper detection."""

import json

import pytest

from osint import evidence, netconfig
from osint.platforms import PLATFORMS


def _r(name, found=False, error=None, source="builtin", **kw):
    return {"platform": name, "url": f"https://{name.lower()}.test/jane", "found": found,
            "error": error, "source": source, "status_code": 200 if found else 404, **kw}


RESULTS = [
    _r("Alpha", found=True),
    _r("Beta", found=True, source="maigret"),
    _r("Gamma"),
    _r("Delta", error="timeout", retried=True),
    _r("Eps", error="connection_error"),
    _r("Zeta", error="unverifiable: platform also reports a random nonexistent username as found",
       control_failed=True),
    _r("Eta", error="heuristic_purge: generic title"),
    _r("Theta", error="waf_blocked: bot-check page detected"),
]
SITES = {r["platform"]: {"url": r["url"], "method": "status_code"} for r in RESULTS}


def _build(results=RESULTS, sites=SITES, tmp="sites.json"):
    return evidence.build(username="jane", results=results, platform_map=sites,
                          started="2026-10-29T10:00:00+00:00", finished="2026-10-29T10:02:00+00:00",
                          wall_seconds=120.04, argv=["helix.py", "-u", "jane", "--all"],
                          concurrency=60, control=True, sites_file=tmp)


def test_counts_are_honest():
    s = evidence.summarise(RESULTS)
    assert s["attempted"] == 8
    assert s["found"] == 2 and s["not_found"] == 1
    assert s["answered"] == 3 and s["unanswered"] == 5
    assert s["answered"] + s["unanswered"] == s["attempted"]
    assert s["retried_after_timeout"] == 1
    r = s["unanswered_by_reason"]
    assert r["timeout"] == 1 and r["connection error"] == 1 and r["bot-check page"] == 1
    assert r["control probe: site finds impossible usernames"] == 1
    assert r["verifier: false-positive pattern"] == 1


def test_fingerprint_is_stable_and_verifies():
    a, b = _build(), _build()
    assert a["fingerprint"] == b["fingerprint"]           # same data, same fingerprint
    assert len(a["fingerprint"]) == 64
    assert evidence.verify(a, SITES) == []
    assert a["database"]["sha256"] == evidence.sha256(evidence.canonical(SITES))


def test_fingerprint_survives_a_json_round_trip(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps(_build(), indent=1))
    assert evidence.verify(json.loads(p.read_text()), SITES) == []


@pytest.mark.parametrize("tamper", [
    lambda e: e["summary"].__setitem__("found", 3),
    lambda e: e["attempt"].__setitem__("wall_seconds", 59.0),
    lambda e: e["found"].append({"platform": "Fake", "url": "x", "source": "builtin"}),
    lambda e: e["per_site"][0].__setitem__("found", not e["per_site"][0]["found"]),
])
def test_any_edit_breaks_the_fingerprint(tamper):
    ev = _build()
    tamper(ev)
    assert "fingerprint does not match the file's contents" in evidence.verify(ev)


def test_a_different_sites_file_is_detected():
    ev = _build()
    other = dict(SITES, Extra={"url": "https://x.test/{username}"})
    assert evidence.verify(ev, other) == ["sites file does not match the database hash in the evidence"]


def test_order_of_results_does_not_change_the_evidence():
    assert _build(list(reversed(RESULTS)))["fingerprint"] == _build()["fingerprint"]


def test_proxy_credentials_never_reach_the_evidence():
    netconfig.set_proxy("http://user:secret@10.0.0.5:3128")
    ev = evidence.build(username="jane", results=RESULTS, platform_map=SITES,
                        started="s", finished="f", wall_seconds=1, concurrency=60, control=True,
                        argv=["helix", "-u", "jane", "--proxy", "http://user:secret@10.0.0.5:3128"],
                        sites_file="x")
    assert "secret" not in json.dumps(ev)


def test_the_real_database_is_canonicalisable():
    """The built-in platform map must hash; a set or object in it would crash a record run."""
    assert len(evidence.sha256(evidence.canonical(PLATFORMS))) == 64


def test_write_and_cli_round_trip(tmp_path, capsys):
    ev = evidence.write(str(tmp_path), "jane", dict(
        username="jane", results=RESULTS, platform_map=SITES, started="s", finished="f",
        wall_seconds=1.0, argv=["helix"], concurrency=60, control=True))
    paths = ev["_paths"]
    assert evidence.main([paths["evidence"], paths["sites"]]) == 0
    assert "OK" in capsys.readouterr().out

    data = json.loads(open(paths["evidence"]).read())
    data["summary"]["found"] = 99
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data))
    assert evidence.main([str(bad)]) == 1


@pytest.mark.parametrize("status,answered", [(404, True), (200, True), (410, True),
                                             (403, False), (429, False), (503, False), (999, False)])
def test_blocked_or_failed_negatives_are_not_answers(status, answered):
    r = {"platform": "X", "found": False, "error": None, "status_code": status}
    s = evidence.summarise([r])
    assert s["answered"] == (1 if answered else 0)
    assert s["answered"] + s["unanswered"] == 1
    if not answered:
        assert f"HTTP {status}" in next(iter(s["unanswered_by_reason"]))


@pytest.mark.parametrize("error,reason", [
    ("502, message='Bad Gateway', url='http://127.0.0.1:3128'", "proxy refused the host (HTTP 502 from the proxy)"),
    ("Server disconnected", "connection error"),
    ("400, message='Got more than 8190 bytes when reading: b'x'", "oversized response header"),
    ("unexpected: Failed to perform, curl: (28) Connection timed out", "timeout"),
])
def test_rehearsal_errors_are_named(error, reason):
    assert evidence.reason_of(error) == reason


def test_compressed_evidence_verifies(tmp_path):
    import gzip
    ev = evidence.write(str(tmp_path), "jane", dict(
        username="jane", results=RESULTS, platform_map=SITES, started="s", finished="f",
        wall_seconds=1.0, argv=["helix"], concurrency=60, control=True))
    for key in ("evidence", "sites"):
        src = ev["_paths"][key]
        with open(src, "rb") as f, gzip.open(src + ".gz", "wb") as g:
            g.write(f.read())
    assert evidence.main([ev["_paths"]["evidence"] + ".gz", ev["_paths"]["sites"] + ".gz"]) == 0


def test_the_published_record_rehearsal_verifies():
    """bench/results carries the sealed made-up-name rehearsal; it must stay intact."""
    import glob, os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ev = glob.glob(os.path.join(root, "bench/results/*record_rehearsal*/*_evidence.json.gz"))
    assert ev, "the published rehearsal evidence is missing"
    for e in ev:
        sites = e.replace("_evidence.json.gz", "_sites.json.gz")
        data = evidence._load_json(e)
        assert evidence.verify(data, evidence._load_json(sites)) == []
        assert data["summary"]["found"] == 0          # a made-up name: every hit would be false
        assert data["summary"]["attempted"] >= 8000


def test_commit_is_only_reported_from_a_helix_checkout(monkeypatch):
    """A venv inside another project's repo must not report that project's commit."""
    calls = []

    def fake_check_output(cmd, **kw):
        calls.append(cmd)
        if "--show-toplevel" in cmd:
            return b"/home/someone/their-project\n"
        return b"deadbeef\n"

    monkeypatch.setattr(evidence.subprocess, "check_output", fake_check_output)
    assert evidence._git_commit() == "installed package (no git checkout)"
    assert not any("HEAD" in c and "--show-toplevel" not in c for c in calls)


def test_commit_is_reported_from_this_checkout():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(evidence.__file__)))
    if not os.path.exists(os.path.join(root, ".git")):
        pytest.skip("not a git checkout (unpacked sdist, distro build)")
    c = evidence._git_commit()
    assert c != "installed package (no git checkout)" and len(c.split("-")[0]) == 40


@pytest.mark.parametrize("argv", [
    ["helix", "--proxy", "socks5://user:secret@10.0.0.5:1080"],
    ["helix", "--proxy=http://user:secret@10.0.0.5:3128"],
    ["helix", "--prox", "socks5://user:secret@h:1"],          # abbreviation
    ["helix", "-u", "x", "http://user:secret@anything"],
])
def test_credentials_never_reach_the_recorded_command(argv):
    assert "secret" not in " ".join(evidence._redact_argv(argv))


def test_abbreviated_flags_are_refused():
    import subprocess, sys, os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([sys.executable, "helix.py", "--prox", "http://u:p@h:1", "-u", "x"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "unrecognized arguments" in r.stderr


def test_verifier_output_is_terminal_safe(tmp_path, capsys, monkeypatch):
    import sys
    from osint import termsafe
    monkeypatch.setattr(sys, "stdout", sys.stdout)       # restored after the test
    ev = evidence.write(str(tmp_path), "jane", dict(
        username="jane\x1b[8m\x1b]0;x\x07", results=RESULTS, platform_map=SITES, started="s",
        finished="f", wall_seconds=1.0, argv=["helix"], concurrency=60, control=True))
    evidence.main([ev["_paths"]["evidence"]])
    assert isinstance(sys.stdout, termsafe.TerminalSafe)
    out = capsys.readouterr().out
    assert "\x1b[8m" not in out and "\x07" not in out


@pytest.mark.parametrize("content", [None, b"not json", b"\x1f\x8b broken gzip", b'{"a": 1}', b"[]"])
def test_unreadable_or_foreign_files_fail_cleanly(tmp_path, capsys, content):
    p = tmp_path / ("x.json.gz" if content and content.startswith(b"\x1f\x8b") else "x.json")
    if content is not None:
        p.write_bytes(content)
    assert evidence.main([str(p)]) == 2
    assert capsys.readouterr().out.startswith("FAIL:")
