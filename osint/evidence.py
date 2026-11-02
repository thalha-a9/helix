"""
Helix: record-attempt evidence.

`--record-attempt` turns a scan into evidence a third party can check:

  <label>_evidence.json   every number about the run, the outcome for every
                          site, and a SHA-256 fingerprint of the whole file
  <label>_sites.json      the exact site definitions scanned, in canonical
                          form; its SHA-256 is recorded in the evidence

The fingerprint is printed large at the end of the run so a screen recording
of the attempt shows it, tying the video to this one file: change one byte
of the evidence and the fingerprint no longer matches.

Counting rules (stated in the file so nobody has to guess):
  attempted  every site in the database
  answered   sites that gave a clear answer: found, or a definite "not found"
  found      accounts that survived the control probe and the verifier
  every other site is counted under the reason it gave no clear answer
"""

import hashlib
import json
import os
import platform as _platform
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from osint import __version__, netconfig

SCHEMA = "helix.record-attempt.v1"

COUNTING_RULES = {
    "attempted": "every site definition in the scanned database",
    "answered": "sites that gave a clear answer: an account found, or a definite 'not found'. "
                "A 'not found' that came with HTTP 401/403/407/408/425/429/451/999 or 5xx is "
                "counted as no clear answer",
    "found": "accounts kept after the live control probe (re-check + two impossible "
             "usernames) and the local verifier",
    "unanswered": "sites with no clear answer, counted by reason (timeout, connection "
                  "error, bot check, control probe could not verify, ...)",
}

# error prefix -> reason bucket
_REASONS = (
    ("timeout", "timeout"),
    ("connection_error", "connection error"),
    ("waf_blocked", "bot-check page"),
    ("requires curl_cffi", "needs curl_cffi (not installed)"),
    ("unverifiable: platform also reports", "control probe: site finds impossible usernames"),
    ("unverifiable: no clear", "control probe: impossible username got no clear answer"),
    ("unverifiable: hit did not reproduce", "control probe: hit did not reproduce"),
    ("unconfirmed: a made-up name the same length", "unconfirmed: a same-length made-up name was also found"),
    ("heuristic_purge", "verifier: false-positive pattern"),
    ("soft404_body", "verifier: not-found page"),
    ("Server disconnected", "connection error"),
    ("Cannot connect", "connection error"),
    ("502, message='Bad Gateway', url='http", "proxy refused the host (HTTP 502 from the proxy)"),
    ("unexpected: Failed to perform, curl: (28)", "timeout"),
    ("400, message='Got more than", "oversized response header"),
)


def reason_of(error: str) -> str:
    for prefix, label in _REASONS:
        if error.startswith(prefix):
            return label
    return "other error"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(obj) -> bytes:
    """Byte-stable JSON: same data, same bytes, same hash, on any machine."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_commit() -> str:
    """Helix's own commit, only when running from a Helix checkout. An install
    inside someone else's repository (a venv in a project) must not report
    that project's commit as Helix's."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        top = subprocess.check_output(["git", "-C", root, "rev-parse", "--show-toplevel"],
                                      stderr=subprocess.DEVNULL, timeout=5).decode().strip()
        if os.path.realpath(top) != os.path.realpath(root) or \
                not os.path.exists(os.path.join(root, "helix.py")):
            return "installed package (no git checkout)"
        out = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"],
                                      stderr=subprocess.DEVNULL, timeout=5)
        dirty = subprocess.call(["git", "-C", root, "diff", "--quiet", "HEAD"],
                                stderr=subprocess.DEVNULL, timeout=5) != 0
        return out.decode().strip() + ("-dirty" if dirty else "")
    except Exception:
        return "not a git checkout"


# A "not found" that came with one of these statuses is not an answer: the
# site refused, rate-limited or failed, it did not say the user is absent.
# (Some sites do answer 403 for unknown users; a record counts conservatively.)
NO_ANSWER_STATUSES = {401, 403, 407, 408, 425, 429, 451, 999} | set(range(500, 600))


def _no_answer(r: dict) -> str:
    """'' when the result is a clear answer, else the reason it is not."""
    if r.get("found"):
        return ""
    if r.get("error"):
        return reason_of(str(r["error"]))
    status = r.get("status_code")
    if status in NO_ANSWER_STATUSES:
        return f"blocked or failed (HTTP {status})"
    return ""


def summarise(results: List[dict]) -> Dict:
    attempted = len(results)
    found = [r for r in results if r.get("found")]
    reasons = Counter(why for why in map(_no_answer, results) if why)
    clean_negative = [r for r in results if not r.get("found") and not _no_answer(r)]
    retried = sum(1 for r in results if r.get("retried"))
    return {
        "attempted": attempted,
        "answered": len(found) + len(clean_negative),
        "found": len(found),
        "not_found": len(clean_negative),
        "unanswered": attempted - len(found) - len(clean_negative),
        "unanswered_by_reason": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
        "retried_after_timeout": retried,
        "sources": dict(Counter(r.get("source", "builtin") for r in results)),
    }


def build(*, username: str, results: List[dict], platform_map: Dict[str, dict],
          started: str, finished: str, wall_seconds: float, argv: List[str],
          concurrency: int, control: bool, sites_file: str, pages: Optional[Dict] = None,
          target_type: str = "username") -> Dict:
    """The evidence record, with `fingerprint` = SHA-256 of everything else.

    For an email scan `username` holds the address and target_type is "email";
    username records leave the key out, so their bytes stay as they were."""
    sites_hash = sha256(canonical(platform_map))
    per_site = sorted(
        ({"platform": r.get("platform"), "source": r.get("source"), "url": r.get("url"),
          "found": bool(r.get("found")), "status": r.get("status_code"),
          "error": r.get("error") or None,
          **({"page_sha256": r["page_sha256"]} if r.get("page_sha256") else {})}
         for r in results),
        key=lambda x: str(x["platform"]).lower())
    body = {
        "schema": SCHEMA,
        "tool": {"name": "Helix", "version": __version__, "commit": _git_commit(),
                 "homepage": "https://github.com/thalha-a9/helix"},
        "attempt": {
            "username": username,
            "started_utc": started,
            "finished_utc": finished,
            "wall_seconds": round(wall_seconds, 1),
            "command": " ".join(_redact_argv(argv)),
            "concurrency": concurrency,
            "control_probe": control,
            **({"target_type": target_type} if target_type != "username" else {}),
        },
        "environment": {
            "python": _platform.python_version(),
            "os": f"{_platform.system()} {_platform.release()}",
            "machine": _platform.machine(),
            "cpus": os.cpu_count(),
            "egress": netconfig.describe(),
        },
        "database": {
            "sites": len(platform_map),
            "sha256": sites_hash,
            "file": os.path.basename(sites_file),
        },
        "counting_rules": COUNTING_RULES,
        **({"pages": {"dir": os.path.basename(pages["_dir"]), "count": len(pages["pages"]),
                      "manifest_sha256": pages["_sha256"]}} if pages else {}),
        "summary": summarise(results),
        "found": [{"platform": r["platform"], "url": r.get("url"), "source": r.get("source")}
                  for r in sorted(results, key=lambda x: str(x.get("platform")).lower())
                  if r.get("found")],
        "per_site": per_site,
    }
    body["fingerprint"] = sha256(canonical(body))
    return body


def verify(evidence: Dict, sites: Optional[Dict] = None) -> List[str]:
    """Problems with an evidence file (and its sites file); [] when it checks out."""
    problems = []
    body = {k: v for k, v in evidence.items() if k != "fingerprint"}
    if sha256(canonical(body)) != evidence.get("fingerprint"):
        problems.append("fingerprint does not match the file's contents")
    if sites is not None and sha256(canonical(sites)) != evidence.get("database", {}).get("sha256"):
        problems.append("sites file does not match the database hash in the evidence")
    s = evidence.get("summary", {})
    if s.get("answered", 0) + s.get("unanswered", 0) != s.get("attempted"):
        problems.append("answered + unanswered does not equal attempted")
    if s.get("found") != len(evidence.get("found", [])):
        problems.append("found count does not match the found list")
    return problems


def write(out_dir: str, label: str, evidence_kwargs: Dict) -> Dict:
    """Write <label>_sites.json and <label>_evidence.json; return the evidence."""
    platform_map = evidence_kwargs["platform_map"]
    sites_path = os.path.join(out_dir, f"{label}_sites.json")
    with open(sites_path, "wb") as f:
        f.write(canonical(platform_map))
    ev = build(sites_file=sites_path, **evidence_kwargs)
    ev_path = os.path.join(out_dir, f"{label}_evidence.json")
    with open(ev_path, "w", encoding="utf-8") as f:
        json.dump(ev, f, indent=1, ensure_ascii=False)
    ev["_paths"] = {"evidence": ev_path, "sites": sites_path}
    return ev


_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]+@")


def _redact_argv(argv: List[str]) -> List[str]:
    """Any user:pass@ in any argument is removed, whatever flag it came with."""
    return [_CREDENTIALS.sub(r"\1***@", str(a)) for a in argv]


def _load_json(path: str):
    """Plain or gzip-compressed (.gz) JSON: published records are compressed."""
    import gzip
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def main(argv: Optional[List[str]] = None) -> int:
    """python -m osint.evidence EVIDENCE.json [SITES.json]: check a record file."""
    argv = sys.argv[1:] if argv is None else argv
    from osint.termsafe import install as _safe_terminal
    _safe_terminal()          # the file may come from someone else: no escapes
    if not argv:
        print(main.__doc__)
        return 2
    try:
        ev = _load_json(argv[0])
        sites = _load_json(argv[1]) if len(argv) > 1 else None
    except (OSError, ValueError, EOFError) as e:
        print(f"FAIL: cannot read the evidence: {e.__class__.__name__}: {e}")
        return 2
    if not isinstance(ev, dict) or "fingerprint" not in ev or "summary" not in ev:
        print("FAIL: not a Helix evidence file")
        return 2
    problems = verify(ev, sites)
    if ev.get("pages"):
        from osint import capture
        pdir = os.path.join(os.path.dirname(os.path.abspath(argv[0])), ev["pages"]["dir"])
        if os.path.isdir(pdir):
            problems += capture.verify(pdir, ev["pages"]["manifest_sha256"])
            if not problems:
                print(f"pages: {ev['pages']['count']} saved page(s) re-hashed, all intact")
        else:
            print(f"pages: {ev['pages']['dir']} is not next to the evidence file; not checked")
    s = ev.get("summary", {})
    print(f"Helix {ev['tool']['version']} | {ev['attempt']['username']} | "
          f"{ev['attempt']['started_utc']} -> {ev['attempt']['finished_utc']}")
    print(f"attempted {s.get('attempted')} | answered {s.get('answered')} | found {s.get('found')} | "
          f"{ev['attempt']['wall_seconds']} s")
    print(f"fingerprint {ev.get('fingerprint')}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print("OK: the evidence file is intact" + (" and matches the sites file" if sites else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
