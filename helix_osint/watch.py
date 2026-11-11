"""
Helix: watch a username over time (--watch).

Every scan run with --watch adds one snapshot to a history kept next to the
results and says what changed since the snapshot before it:

  new          an account found now on a site that clearly said "no such
               user" last time
  first seen   an account found now on a site that was not scanned last
               time, or gave no clear answer then: it may be older than this
               scan, so it is not called new
  removed      an account found last time on a site that clearly says "no
               such user" now
  not checked  an account found last time on a site that gave no clear
               answer now, or was not scanned: it is not called removed
  changed      an account found both times whose public facts differ (the
               name on the profile, the bio, the links it lists, the places
               it names, its picture)

A site that did not answer never counts as "no account": that is the rule
for every Helix count, and it holds here in both directions.

The history is a chain. Each snapshot carries the SHA-256 of the one before
it and its own, so a snapshot cannot be changed, removed or slipped in later
without breaking every hash after it. `helix --verify-watch DIR` re-checks
the chain.

  <label>_watch/history.jsonl       one snapshot a line
  <label>_watch/sites_<hash>.json   the site list a snapshot was taken on,
                                    written once per distinct list
"""

import json
import os
from typing import Dict, List, Optional, Tuple

from helix_osint import __version__
from helix_osint.evidence import PURPOSE_NOT_STATED, _no_answer, canonical, one_line, sha256
from helix_osint.platform_schema import profile_key

SCHEMA = "helix.watch.v1"

# The public facts of a found account that are compared between snapshots,
# and what each is called in the report.
FACTS = (("name", "og_title", "name on the profile"),
         ("bio", "declared_bio", "bio"),
         ("links", "bio_links", "links it lists"),
         ("places", "location_hints", "places it names"),
         ("picture", "phash", "profile picture"))


def _facts(result: dict) -> dict:
    out = {}
    for key, field, _label in FACTS:
        value = result.get(field)
        if isinstance(value, dict):
            value = sorted(f"{k}: {v}" for k, v in value.items())
        elif isinstance(value, (list, tuple, set)):
            value = sorted(str(v) for v in value)
        if value:
            out[key] = value
    return out


def snapshot(username: str, results: List[dict], platform_map: Dict[str, dict],
             taken_utc: str, left_out: int = 0, purpose: str = "") -> dict:
    """What this scan saw, in the form the history keeps (without the chain)."""
    accounts, unanswered, keys = {}, [], []
    for r in results:
        pdef = platform_map.get(r.get("platform")) or {}
        key = profile_key(pdef.get("url") or r.get("url") or "")
        keys.append(key)
        if r.get("found"):
            accounts[key] = {"platform": r.get("platform"), "url": r.get("url"), "facts": _facts(r)}
        elif _no_answer(r):
            unanswered.append(key)
    keys = sorted(set(keys))
    return {
        "schema": SCHEMA,
        "username": username,
        "taken_utc": taken_utc,
        "helix": __version__,
        "purpose": one_line(purpose) or PURPOSE_NOT_STATED,
        "sites": len(keys),
        "sites_sha256": sha256(canonical(keys)),
        "answered": len(keys) - len(set(unanswered)),
        "switched_off": left_out,
        "accounts": dict(sorted(accounts.items())),
        "unanswered": sorted(set(unanswered)),
        "_site_keys": keys,                 # written to its own file, not into the chain
    }


def seal(entry: dict, prev_hash: str) -> dict:
    body = {k: v for k, v in entry.items() if k not in ("hash", "_site_keys")}
    body["prev"] = prev_hash
    body["hash"] = sha256(canonical(body))
    return body


def load_history(path: str) -> List[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def verify_history(entries: List[dict]) -> List[str]:
    """Problems with a history; [] when every hash and every link holds."""
    problems, prev = [], ""
    for i, e in enumerate(entries, 1):
        if not isinstance(e, dict) or e.get("schema") != SCHEMA:
            problems.append(f"snapshot {i} is not a Helix watch snapshot")
            prev = e.get("hash", "") if isinstance(e, dict) else ""
            continue
        body = {k: v for k, v in e.items() if k != "hash"}
        if sha256(canonical(body)) != e.get("hash"):
            problems.append(f"snapshot {i} ({e.get('taken_utc')}) was changed after it was written")
        if e.get("prev", "") != prev:
            problems.append(f"snapshot {i} ({e.get('taken_utc')}) does not follow the one before it: "
                            f"a snapshot was removed, added or reordered")
        prev = e.get("hash", "")
    return problems


def _fact_changes(before: dict, after: dict) -> List[str]:
    """Differences in the facts both snapshots hold. A fact one of them lacks
    (the picture is only hashed with --phash) is not a change."""
    out = []
    for key, _field, label in FACTS:
        a, b = before.get(key), after.get(key)
        if a and b and a != b:
            if isinstance(a, list) or isinstance(b, list):
                gone = [x for x in a if x not in b]
                came = [x for x in b if x not in a]
                parts = ([f"added {', '.join(came)}"] if came else []) + \
                        ([f"dropped {', '.join(gone)}"] if gone else [])
                out.append(f"{label}: {'; '.join(parts)}")
            else:
                out.append(f"{label}: {a!r} is now {b!r}")
    return out


def diff(prev: dict, now: dict, prev_sites: Optional[set] = None,
         now_sites: Optional[set] = None) -> Dict[str, list]:
    """
    What changed between two snapshots. `prev_sites` and `now_sites` are the
    site lists the snapshots were taken on; without the earlier list a site
    is taken to have been scanned then only when both lists are the same.
    """
    same_list = prev.get("sites_sha256") == now.get("sites_sha256")
    now_keys = now_sites if now_sites is not None else set(now.get("_site_keys") or [])

    def scanned_before(key: str) -> bool:
        if prev_sites is not None:
            return key in prev_sites
        return same_list

    def scanned_now(key: str) -> bool:
        return key in now_keys if now_keys else same_list

    was, is_ = prev.get("accounts", {}), now.get("accounts", {})
    silent_before, silent_now = set(prev.get("unanswered", [])), set(now.get("unanswered", []))
    out = {"new": [], "first_seen": [], "removed": [], "not_checked": [], "changed": []}
    for key, acc in is_.items():
        item = {"platform": acc["platform"], "url": acc["url"]}
        if key in was:
            changes = _fact_changes(was[key].get("facts", {}), acc.get("facts", {}))
            if changes:
                out["changed"].append({**item, "changes": changes})
        elif key in silent_before:
            out["first_seen"].append({**item, "why": "the site gave no clear answer last time"})
        elif not scanned_before(key):
            out["first_seen"].append({**item, "why": "the site was not scanned last time"})
        else:
            out["new"].append(item)
    for key, acc in was.items():
        if key in is_:
            continue
        item = {"platform": acc["platform"], "url": acc["url"]}
        if key in silent_now:
            out["not_checked"].append({**item, "why": "the site gave no clear answer this time"})
        elif not scanned_now(key):
            out["not_checked"].append({**item, "why": "the site was not scanned this time"})
        else:
            out["removed"].append(item)
    for items in out.values():
        items.sort(key=lambda x: str(x["platform"]).lower())
    return out


def _sites_file(folder: str, digest: str) -> str:
    return os.path.join(folder, f"sites_{digest[:16]}.json")


def _read_sites(folder: str, digest: str) -> Optional[set]:
    try:
        with open(_sites_file(folder, digest), encoding="utf-8") as f:
            keys = json.load(f)
    except (OSError, ValueError):
        return None
    return set(keys) if isinstance(keys, list) and sha256(canonical(sorted(keys))) == digest else None


def record(out_dir: str, label: str, snap: dict) -> Tuple[dict, Optional[dict], Optional[dict], str]:
    """
    Add a snapshot to the history. Returns (the sealed snapshot, the one
    before it or None, the differences or None, the history path). A history
    that fails its own check is not added to: ValueError names what is wrong.
    """
    folder = os.path.join(out_dir, f"{label}_watch")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "history.jsonl")
    history = load_history(path)
    broken = verify_history(history)
    if broken:
        raise ValueError("; ".join(broken))
    prev = history[-1] if history else None
    if prev and prev.get("username", "").lower() != snap["username"].lower():
        raise ValueError(f"this history is for {prev.get('username')}, not {snap['username']}")
    sites_path = _sites_file(folder, snap["sites_sha256"])
    if not os.path.exists(sites_path):
        with open(sites_path, "w", encoding="utf-8") as f:
            json.dump(snap["_site_keys"], f)
    changes = None
    if prev:
        changes = diff(prev, snap, _read_sites(folder, prev.get("sites_sha256", "")),
                       set(snap["_site_keys"]))
    sealed = seal(snap, prev["hash"] if prev else "")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(sealed, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return sealed, prev, changes, path


def summary_lines(sealed: dict, prev: Optional[dict], changes: Optional[dict], count: int) -> List[str]:
    """The report for the terminal, plain text, one item a line."""
    if prev is None:
        return [f"First snapshot: {len(sealed['accounts'])} account(s) on record. "
                f"Run the same command again later to see what changed."]
    lines = [f"Snapshot {count}, compared with {prev['taken_utc']}:"]
    labels = (("new", "new"), ("removed", "removed"), ("changed", "changed"),
              ("first_seen", "first seen"), ("not_checked", "not checked"))
    for key, label in labels:
        for item in changes[key]:
            extra = "; ".join(item.get("changes", [])) or item.get("why", "")
            lines.append(f"[{label}] {item['platform']}  {item['url']}" + (f"  ({extra})" if extra else ""))
    if not any(changes.values()):
        lines.append(f"No change: the same {len(sealed['accounts'])} account(s).")
    return lines


def main(argv: List[str]) -> int:
    """helix --verify-watch DIR: re-check a watch history."""
    from helix_osint.termsafe import install as _safe_terminal
    _safe_terminal()
    target = argv[0]
    path = os.path.join(target, "history.jsonl") if os.path.isdir(target) else target
    try:
        history = load_history(path)
    except (OSError, ValueError) as e:
        print(f"FAIL: cannot read the history: {e.__class__.__name__}: {e}")
        return 2
    if not history:
        print(f"FAIL: no snapshots in {path}")
        return 2
    problems = verify_history(history)
    print(f"{history[0].get('username')} | {len(history)} snapshot(s) | "
          f"{history[0].get('taken_utc')} -> {history[-1].get('taken_utc')}")
    print(f"last hash {history[-1].get('hash')}")
    for p in problems:
        print(f"FAIL: {p}")
    if not problems:
        print("OK: every snapshot is intact and follows the one before it")
    return 1 if problems else 0
