"""
The open accuracy test: username tools scored on real accounts whose owners
agreed (see bench/ACCURACY.md).

    python -m bench.compare --truth volunteers/ --tools helix,sherlock,maigret \\
           --results blackbird=blackbird_urls/ --out bench/results/accuracy.json

Each volunteer file says which profile addresses are theirs (`has`) and on
which sites they hold no account (`has_not`). A tool is run on the username
and its reported addresses are scored against that:

  found    an address in `has` that the tool reported
  missed   an address in `has` that it did not report
  wrong    a report on a `has_not` site, and, when the volunteer marked the
           list `complete`, any report that is not in `has`
  unknown  any other report: counted neither way

helix, sherlock and maigret are run by this harness, one after the other in
a random order, each timed. Another tool is scored from a folder of its
results (`--results name=folder`): one text file per username, one profile
address a line.
"""

import argparse
import glob
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

FOUND_LINE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)\s*$")

# The command each tool documents for a full scan of one username.
COMMANDS = {
    "helix": lambda exe, user, work: [exe, "-u", user, "--all", "--no-browser", "--output", "out"],
    "sherlock": lambda exe, user, work: [exe, user, "--print-found", "--no-color"],
    "maigret": lambda exe, user, work: [exe, user, "-a", "--no-progressbar", "--no-color", "--no-recursion"],
}


def address_key(url: str) -> str:
    """A profile address as it is compared: no scheme, no www, no trailing
    slash, lower case."""
    u = re.sub(r"^https?://", "", (url or "").strip().lower())
    return re.sub(r"^(www|m|mobile)\.", "", u).rstrip("/")


def site_of(url: str) -> str:
    host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def on_site(url: str, site: str) -> bool:
    host, site = site_of(url), site_of(site)
    return bool(site) and (host == site or host.endswith("." + site))


def parse_found(output: str) -> List[str]:
    """Profile addresses from a tool's terminal output: the "[+] Site: URL"
    lines Sherlock and Maigret print. Colour codes are removed first."""
    plain = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    return [m.group(2) for m in map(FOUND_LINE.match, plain.splitlines()) if m]


def helix_found(work: str) -> List[str]:
    """The confirmed accounts from Helix's JSON report in `work`/out."""
    for path in sorted(glob.glob(os.path.join(work, "out", "*_2*.json")), reverse=True):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return [r["url"] for r in data.get("found") or []
                if r.get("found") and r.get("target_type", "username") == "username"]
    return []


def load_truth(path: str) -> List[dict]:
    files = sorted(glob.glob(os.path.join(path, "*.json"))) if os.path.isdir(path) else [path]
    out = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            t = json.load(fh)
        if not t.get("username") or not isinstance(t.get("has"), list):
            raise ValueError(f"{f}: a volunteer file needs a username and a list of addresses under 'has'")
        if not str(t.get("consent") or "").strip():
            raise ValueError(f"{f}: no consent statement, so it cannot be used")
        t.setdefault("has_not", [])
        t.setdefault("complete", False)
        out.append(t)
    return out


def score(truth: dict, reported: List[str]) -> Dict:
    has = {address_key(u): u for u in truth["has"]}
    seen = {address_key(u): u for u in reported}
    found = sorted(has[k] for k in has if k in seen)
    missed = sorted(has[k] for k in has if k not in seen)
    wrong, unknown = [], []
    for k, url in seen.items():
        if k in has:
            continue
        if any(on_site(url, s) for s in truth["has_not"]) or truth.get("complete"):
            wrong.append(url)
        else:
            unknown.append(url)
    n_found, n_wrong, n_missed = len(found), len(wrong), len(missed)
    return {
        "reported": len(seen), "found": n_found, "missed": n_missed, "wrong": n_wrong,
        "unknown": len(unknown),
        "precision": round(n_found / (n_found + n_wrong), 4) if n_found + n_wrong else None,
        "recall": round(n_found / (n_found + n_missed), 4) if n_found + n_missed else None,
        "found_list": found, "missed_list": missed, "wrong_list": sorted(wrong),
    }


def run_tool(tool: str, username: str, timeout: int = 3600, exe: Optional[str] = None) -> Dict:
    """Run one tool on one username in an empty folder. Returns the addresses
    it reported, the seconds it took, and its version line."""
    exe = exe or shutil.which(tool) or (shutil.which("helix-osint") if tool == "helix" else None)
    if not exe:
        return {"error": f"{tool} is not installed", "reported": [], "seconds": None}
    work = tempfile.mkdtemp(prefix=f"compare_{tool}_")
    try:
        version = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60, cwd=work)
        started = time.time()
        proc = subprocess.run(COMMANDS[tool](exe, username, work), capture_output=True, text=True,
                              timeout=timeout, cwd=work)
        seconds = round(time.time() - started, 1)
        reported = helix_found(work) if tool == "helix" else parse_found(proc.stdout)
        return {"reported": reported, "seconds": seconds, "exit_code": proc.returncode,
                "version": (version.stdout or version.stderr).strip().splitlines()[0][:80]
                if (version.stdout or version.stderr).strip() else ""}
    except subprocess.TimeoutExpired:
        return {"error": f"{tool} did not finish in {timeout} s", "reported": [], "seconds": None}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def read_results(folder: str, username: str) -> Optional[List[str]]:
    """A tool's saved results for one username: <folder>/<username>.txt."""
    path = os.path.join(folder, f"{username}.txt")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip().startswith(("http://", "https://"))]


def totals(rows: List[dict]) -> Dict:
    found = sum(r["found"] for r in rows)
    missed = sum(r["missed"] for r in rows)
    wrong = sum(r["wrong"] for r in rows)
    timed = [r["seconds"] for r in rows if r.get("seconds") is not None]
    return {"volunteers": len(rows), "found": found, "missed": missed, "wrong": wrong,
            "precision": round(found / (found + wrong), 4) if found + wrong else None,
            "recall": round(found / (found + missed), 4) if found + missed else None,
            "seconds_total": round(sum(timed), 1) if timed else None}


def compare(truths: List[dict], tools: List[str], saved: Dict[str, str], timeout: int = 3600,
            seed: Optional[int] = None, run=run_tool) -> Dict:
    rng = random.Random(seed)
    per_tool: Dict[str, List[dict]] = {t: [] for t in list(tools) + list(saved)}
    for truth in truths:
        order = list(tools)
        rng.shuffle(order)                       # no tool always goes first on a warm cache
        for tool in order:
            ran = run(tool, truth["username"], timeout)
            row = {"username": truth["username"], "seconds": ran.get("seconds"),
                   "version": ran.get("version", ""), **score(truth, ran["reported"])}
            if ran.get("error"):
                row["error"] = ran["error"]
            per_tool[tool].append(row)
        for tool, folder in saved.items():
            reported = read_results(folder, truth["username"])
            row = {"username": truth["username"], "seconds": None, **score(truth, reported or [])}
            if reported is None:
                row["error"] = f"no results file for {truth['username']} in {folder}"
            per_tool[tool].append(row)
    return {"schema": "helix.accuracy.v1", "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "volunteers": [{"username": t["username"], "has": len(t["has"]), "has_not": len(t["has_not"]),
                            "complete": bool(t["complete"])} for t in truths],
            "tools": {tool: {"totals": totals(rows), "per_volunteer": rows} for tool, rows in per_tool.items()}}


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m bench.compare", description=__doc__.split("\n\n")[0])
    p.add_argument("--truth", required=True, help="a volunteer file, or a folder of them")
    p.add_argument("--tools", default="helix", help="comma list of helix, sherlock, maigret")
    p.add_argument("--results", action="append", default=[], metavar="NAME=FOLDER",
                   help="score another tool from saved results (one <username>.txt per volunteer)")
    p.add_argument("--timeout", type=int, default=3600, help="seconds allowed per tool and username")
    p.add_argument("--seed", type=int, default=None, help="fix the random running order")
    p.add_argument("--out", default=None, help="write the full result as JSON")
    args = p.parse_args(argv)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in COMMANDS]
    if unknown:
        print(f"Unknown tool(s): {', '.join(unknown)}. Run them yourself and pass --results NAME=FOLDER.")
        return 2
    saved = dict(item.split("=", 1) for item in args.results)
    report = compare(load_truth(args.truth), tools, saved, args.timeout, args.seed)
    print(f"{'tool':<12}{'found':>7}{'missed':>8}{'wrong':>7}{'precision':>11}{'recall':>8}{'seconds':>10}")
    for tool, data in report["tools"].items():
        t = data["totals"]
        print(f"{tool:<12}{t['found']:>7}{t['missed']:>8}{t['wrong']:>7}"
              f"{t['precision'] if t['precision'] is not None else 'n/a':>11}"
              f"{t['recall'] if t['recall'] is not None else 'n/a':>8}"
              f"{t['seconds_total'] if t['seconds_total'] is not None else 'n/a':>10}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1, ensure_ascii=False)
        print(f"Written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
