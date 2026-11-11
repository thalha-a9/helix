"""The open accuracy test: how tools are scored against a volunteer's own list."""

import json

import pytest

from bench import compare

TRUTH = {"username": "janeroe", "complete": False, "consent": "Jane Roe, 10 Nov 2026, I agree.",
         "has": ["https://github.com/janeroe", "https://lobste.rs/~janeroe"],
         "has_not": ["reddit.com", "instagram.com"]}


def test_reports_are_scored_as_found_missed_wrong_or_unknown():
    s = compare.score(TRUTH, ["http://www.github.com/JaneRoe/", "https://old.reddit.com/user/janeroe",
                              "https://forum.example/u/janeroe"])
    assert (s["found"], s["missed"], s["wrong"], s["unknown"]) == (1, 1, 1, 1)
    assert s["precision"] == 0.5 and s["recall"] == 0.5
    assert s["missed_list"] == ["https://lobste.rs/~janeroe"]
    assert s["wrong_list"] == ["https://old.reddit.com/user/janeroe"]


def test_a_complete_list_makes_every_other_report_wrong():
    s = compare.score({**TRUTH, "complete": True}, ["https://github.com/janeroe", "https://forum.example/u/janeroe"])
    assert (s["found"], s["wrong"], s["unknown"]) == (1, 1, 0)


def test_nothing_reported_has_no_precision_and_zero_recall():
    s = compare.score(TRUTH, [])
    assert s["precision"] is None and s["recall"] == 0.0 and s["missed"] == 2


def test_a_site_only_matches_itself_and_its_subdomains():
    assert compare.on_site("https://old.reddit.com/user/x", "reddit.com")
    assert not compare.on_site("https://notreddit.com/x", "reddit.com")
    assert not compare.on_site("https://reddit.com.evil.example/x", "reddit.com")


def test_found_lines_of_sherlock_and_maigret_are_read():
    out = ("[*] Checking username torvalds on:\n"
           "\x1b[32m[+]\x1b[0m GitLab: https://gitlab.com/torvalds\n"
           "[+] Picuki [TikTok]: https://www.tikvib.com/profile/torvalds\n"
           " ├─uid: VXNlcjoxNDA3NjkxMw==\n"
           "[+] Using sites database: /root/.maigret/data.json (8969 sites)\n"
           "[*] Search completed with 2 results\n")
    assert compare.parse_found(out) == ["https://gitlab.com/torvalds", "https://www.tikvib.com/profile/torvalds"]


def test_helix_results_come_from_its_json_report(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    from helix_osint.report import save_json
    save_json("janeroe", [
        {"platform": "GitHub", "url": "https://github.com/janeroe", "found": True},
        {"platform": "X", "url": "https://x.com/janeroe", "found": False},
        {"platform": "Gravatar", "url": "https://gravatar.com/h", "found": True, "target_type": "email"}],
        str(out))
    assert compare.helix_found(str(tmp_path)) == ["https://github.com/janeroe"]


def test_a_volunteer_file_without_consent_is_refused(tmp_path):
    good = tmp_path / "a.json"
    good.write_text(json.dumps(TRUTH))
    assert compare.load_truth(str(tmp_path))[0]["username"] == "janeroe"
    (tmp_path / "b.json").write_text(json.dumps({**TRUTH, "consent": " "}))
    with pytest.raises(ValueError, match="no consent statement"):
        compare.load_truth(str(tmp_path))


def test_tools_are_compared_on_the_same_volunteers_and_saved_results_count_too(tmp_path):
    def fake_run(tool, username, timeout):
        reported = {"helix": ["https://github.com/janeroe", "https://lobste.rs/~janeroe"],
                    "sherlock": ["https://github.com/janeroe", "https://www.instagram.com/janeroe"]}[tool]
        return {"reported": reported, "seconds": 10.0 if tool == "helix" else 20.0, "version": tool + " 1"}

    (tmp_path / "janeroe.txt").write_text("https://lobste.rs/~janeroe\nnot a url\n")
    report = compare.compare([TRUTH], ["helix", "sherlock"], {"blackbird": str(tmp_path)}, seed=1, run=fake_run)
    t = {k: v["totals"] for k, v in report["tools"].items()}
    assert (t["helix"]["precision"], t["helix"]["recall"], t["helix"]["seconds_total"]) == (1.0, 1.0, 10.0)
    assert (t["sherlock"]["precision"], t["sherlock"]["recall"], t["sherlock"]["wrong"]) == (0.5, 0.5, 1)
    assert (t["blackbird"]["found"], t["blackbird"]["missed"], t["blackbird"]["seconds_total"]) == (1, 1, None)
    assert report["volunteers"] == [{"username": "janeroe", "has": 2, "has_not": 2, "complete": False}]
    missing = compare.compare([{**TRUTH, "username": "other"}], [], {"blackbird": str(tmp_path)})
    assert "no results file" in missing["tools"]["blackbird"]["per_volunteer"][0]["error"]


def test_a_missing_tool_is_reported_not_guessed(monkeypatch):
    monkeypatch.setattr(compare.shutil, "which", lambda name: None)
    assert compare.run_tool("sherlock", "janeroe")["error"] == "sherlock is not installed"
    assert compare.main(["--truth", "x", "--tools", "blackbird"]) == 2
