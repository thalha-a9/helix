"""
Helix: the daily site check.

A site list rots: domains expire, forums close, a redesign breaks the rule
that told an account from an empty page. This module checks every site and
keeps the record that lets Helix leave the broken ones out by itself.

One check does two things for every site:

  1. asks for a made-up name. A working site says "no such user";
  2. where a database names an account that exists there, asks for it.
     A working site finds it.

and files the site under one state:

  proven    a real account was found and a made-up name was not
  answers   a made-up name got a clear "no such user"; there is no listed
            account to look for, or the listed one was not found (accounts
            get deleted, so that alone does not make the site broken)
  blocked   the site refused this network: bot check, HTTP 401/403, rate
            limit. It may work from another network, so it is never
            switched off for this
  dead      the host name does not resolve, the certificate is invalid, the
            connection fails or times out, or the server answers 5xx
  broken    the rule cannot tell names apart: it reported an account for a
            made-up name
  unknown   anything else (the checker's own proxy refused the host, a
            needed package is missing)

A site that is dead or broken on OFF_AFTER checks in a row is switched off:
scans leave it out and say how many sites were left out. The first check
that finds it working switches it back on. Checks closer together than
MIN_GAP_HOURS count as one, so a site is off only after failing on
OFF_AFTER separate days.

The check runs from one network. "dead" means dead from there: a site that
drops connections from a data centre can still work from a home line.
`--include-off` scans switched-off sites anyway.

    python -m helix_osint.health check --state status/state.json --out status
    python -m helix_osint.health page  --state status/state.json --out status
"""

import argparse
import asyncio
import html
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from helix_osint import __version__, netconfig
from helix_osint.platform_schema import profile_key

SCHEMA = "helix.site-health.v1"
OFF_SCHEMA = "helix.switched-off.v1"

OFF_AFTER = 3
MIN_GAP_HOURS = 20
KEEP_RUNS = 90

OK_STATES = ("proven", "answers")
FAIL_STATES = ("dead", "broken")
STATES = OK_STATES + ("blocked",) + FAIL_STATES + ("unknown",)

# Where a scan looks for a fresher switched-off list than the one it shipped
# with. The daily check publishes it there.
OFF_URL = "https://raw.githubusercontent.com/thalha-a9/helix/status/switched_off.json"
STATUS_PAGE = "https://thalha-a9.github.io/helix/"
SHIPPED_OFF = Path(__file__).parent / "data" / "switched_off.json"
_CACHE_OFF = Path.home() / ".cache" / "helix" / "switched_off_v1.json"
_MAX_OFF_BYTES = 4 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse(stamp: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None


# One check

def classify(result: dict) -> Tuple[str, str]:
    """(state, why) for a site's answer to a made-up name."""
    from helix_osint.checker import unanswered_kind
    error = str(result.get("error") or "")
    status = result.get("status_code")
    if result.get("found"):
        return "broken", "reported an account for a made-up name"
    if error.startswith("unverifiable: platform also reports"):
        return "broken", "finds made-up names"
    if error.startswith(("unverifiable", "unconfirmed")):
        return "broken", "answers a made-up name differently each time"
    kind = unanswered_kind(result)
    if not kind:
        return "answers", ""
    if kind == "dns":
        return "dead", "host name does not resolve"
    if kind == "certificate":
        return "dead", "invalid HTTPS certificate"
    if kind == "connect":
        return "dead", "connection failed"
    if kind == "timeout":
        return "dead", "no reply in time"
    if kind == "server":
        return "dead", f"server error (HTTP {status})"
    if kind == "botcheck":
        return "blocked", "bot-check page"
    if kind == "rate":
        return "blocked", "rate limit (HTTP 429)"
    if kind == "refused":
        return "blocked", f"refused (HTTP {status})"
    from helix_osint.evidence import _redact_argv
    return "unknown", _redact_argv([error])[0][:60]


async def _look_for_known(platform_map: Dict[str, dict], known: Dict[str, str],
                          concurrency: int, progress_cb=None) -> Dict[str, bool]:
    """{site: True/False} for each site's listed account (`known` maps site
    to account): found, or a clear "no such user". Sites that gave no clear
    answer are left out."""
    from helix_osint.checker import check_platform, unanswered_kind
    out: Dict[str, bool] = {}
    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def one(session, name):
        nonlocal done
        pdef = platform_map[name]
        r = await check_platform(session, name, pdef, known[name], sem, fast=True)
        if unanswered_kind(r):
            r = await check_platform(session, name, pdef, known[name], sem, fast=True)
        if not unanswered_kind(r):
            out[name] = bool(r.get("found"))
        done += 1
        if progress_cb:
            progress_cb(done, len(known))

    connector = netconfig.build_connector(limit=concurrency, force_close=True)
    async with netconfig.new_session(connector=connector) as session:
        await asyncio.gather(*(one(session, n) for n in known))
    return out


async def check(platform_map: Dict[str, dict], concurrency: Optional[int] = None,
                progress_cb=None, known_cb=None) -> Dict[str, dict]:
    """
    Check every site once. Returns {profile key: observation}, an observation
    being {"name", "source", "state", "why"}.
    """
    from helix_osint.checker import CALM_CONCURRENCY, check_username, control_username
    made_up = control_username("")
    results = await check_username(made_up, platforms=platform_map, progress_cb=progress_cb,
                                   concurrency=concurrency, retry_timeouts=True)
    seen: Dict[str, dict] = {}
    by_name: Dict[str, dict] = {}
    for r in results:
        name = r["platform"]
        state, why = classify(r)
        obs = {"name": name, "source": r.get("source") or platform_map[name].get("source", "builtin"),
               "state": state, "why": why}
        by_name[name] = obs
        seen[profile_key(platform_map[name].get("url", ""))] = obs

    answering = [n for n, o in by_name.items() if o["state"] == "answers"]
    with_known = {n: platform_map[n]["known"] for n in answering if platform_map[n].get("known")}
    # A fediverse server names an account of its own (its admin or contact).
    servers = [n for n in answering if n not in with_known and by_name[n]["source"] == "fediverse"]
    if servers:
        from helix_osint.adapters.fediverse_adapter import known_accounts
        with_known.update(await known_accounts(servers, CALM_CONCURRENCY))
    if with_known:
        found = await _look_for_known(platform_map, with_known, CALM_CONCURRENCY, known_cb)
        for name in with_known:
            if found.get(name):
                by_name[name]["state"] = "proven"
            elif name in found:
                by_name[name]["why"] = "the listed test account was not found"
    return seen


# The record

def new_state() -> dict:
    return {"schema": SCHEMA, "updated_utc": "", "last_counted_utc": "", "runs": [], "sites": {}}


def update(state: dict, seen: Dict[str, dict], now_utc: str, seconds: float = 0.0,
           min_gap_hours: float = MIN_GAP_HOURS, where: str = "") -> dict:
    """
    Fold one check into the record. A failed check adds to a site's count
    of failures in a row only when the last counted check was at least
    `min_gap_hours` ago; a working check resets it at once. Sites no longer
    in the database leave the record.
    """
    now, last = _parse(now_utc), _parse(state.get("last_counted_utc", ""))
    counted = last is None or now is None or (now - last).total_seconds() >= min_gap_hours * 3600
    old = state.get("sites", {})
    sites = {}
    for key, obs in seen.items():
        e = dict(old.get(key) or {"fails": 0, "since": now_utc, "last_ok": ""})
        if obs["state"] != e.get("state"):
            e["since"] = now_utc
        if obs["state"] in OK_STATES:
            e["fails"], e["last_ok"] = 0, now_utc
        elif obs["state"] in FAIL_STATES and counted:
            e["fails"] = int(e.get("fails", 0)) + 1
        e.update(name=obs["name"], source=obs["source"], state=obs["state"], why=obs["why"])
        e["off"] = e["state"] in FAIL_STATES and int(e.get("fails", 0)) >= OFF_AFTER
        sites[key] = e
    totals = {s: sum(1 for e in sites.values() if e["state"] == s) for s in STATES}
    run = {"utc": now_utc, "helix": __version__, "sites": len(sites), **totals,
           "off": sum(1 for e in sites.values() if e["off"]),
           "seconds": round(seconds, 1), "counted": counted, **({"where": where} if where else {})}
    return {"schema": SCHEMA, "updated_utc": now_utc,
            "last_counted_utc": now_utc if counted else state.get("last_counted_utc", ""),
            "runs": (state.get("runs", []) + [run])[-KEEP_RUNS:],
            "sites": dict(sorted(sites.items()))}


def switched_off(state: dict) -> dict:
    """The list scans read: every site that is off, with the reason."""
    return {
        "schema": OFF_SCHEMA,
        "updated_utc": state.get("updated_utc", ""),
        "rule": f"dead or broken on {OFF_AFTER} checks in a row; back on at the first "
                f"check that finds it working",
        "sites": {key: {"name": e["name"], "why": e["why"], "since": e["since"]}
                  for key, e in sorted(state.get("sites", {}).items()) if e.get("off")},
    }


# What a scan does with it

def _valid_off(data) -> bool:
    return (isinstance(data, dict) and data.get("schema") == OFF_SCHEMA
            and isinstance(data.get("sites"), dict)
            and all(isinstance(k, str) and isinstance(v, dict) for k, v in data["sites"].items()))


def _read_off(path: Path) -> Optional[dict]:
    from helix_osint.updates import read_json
    return read_json(path, _valid_off, _MAX_OFF_BYTES)


def load_switched_off() -> dict:
    """The newest list at hand: a download from the last day if there is one
    and it is newer, else the list this copy of Helix shipped with."""
    shipped = _read_off(SHIPPED_OFF) or {"schema": OFF_SCHEMA, "updated_utc": "", "sites": {}}
    cached = _read_off(_CACHE_OFF)
    if cached and str(cached.get("updated_utc", "")) > str(shipped.get("updated_utc", "")):
        return cached
    return shipped


async def refresh_switched_off(timeout: float = 8.0, url: str = OFF_URL) -> bool:
    """Fetch today's list once a day. True when a new copy was saved. Any
    failure is silent: the list at hand stays in use."""
    from helix_osint.updates import fetch_daily
    return await fetch_daily(url, _CACHE_OFF, _valid_off, _MAX_OFF_BYTES, timeout)


def apply_switched_off(platform_map: Dict[str, dict], off: dict) -> Tuple[Dict[str, dict], List[dict]]:
    """(sites to scan, sites left out). Each left-out site is
    {"platform", "url", "why", "since"}."""
    listed = (off or {}).get("sites") or {}
    if not listed:
        return platform_map, []
    kept, left_out = {}, []
    for name, pdef in platform_map.items():
        entry = listed.get(profile_key(pdef.get("url", "")))
        if entry is None:
            kept[name] = pdef
        else:
            left_out.append({"platform": name, "url": pdef.get("url", ""),
                             "why": str(entry.get("why", "")), "since": str(entry.get("since", ""))})
    return kept, left_out


# The public page

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Helix site status</title>
<style>
:root { --bg:#ffffff; --fg:#16181d; --dim:#5b6472; --line:#d9dee6; --card:#f5f7fa;
        --ok:#1a7f37; --warn:#9a6700; --bad:#b42318; --link:#0b5fff; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg:#0f1115; --fg:#e7eaf0; --dim:#9aa4b2; --line:#2a2f3a; --card:#171a21;
  --ok:#4ac26b; --warn:#d4a72c; --bad:#ff7b72; --link:#79a8ff; } }
:root[data-theme="dark"] { --bg:#0f1115; --fg:#e7eaf0; --dim:#9aa4b2; --line:#2a2f3a;
  --card:#171a21; --ok:#4ac26b; --warn:#d4a72c; --bad:#ff7b72; --link:#79a8ff; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:1040px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:1.6rem; margin:0 0 4px; } h2 { font-size:1.1rem; margin:32px 0 8px; }
p { margin:8px 0; } .dim { color:var(--dim); } a { color:var(--link); }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:8px; margin:16px 0; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
.tile b { display:block; font-size:1.4rem; font-variant-numeric:tabular-nums; }
.proven b,.answers b { color:var(--ok); } .blocked b { color:var(--warn); }
.dead b,.broken b,.off b { color:var(--bad); }
.controls { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }
input,select { font:inherit; color:var(--fg); background:var(--bg); border:1px solid var(--line);
               border-radius:6px; padding:6px 8px; min-width:0; }
input { flex:1 1 220px; }
.scroll { overflow-x:auto; border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; font-size:.92rem; }
th,td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { background:var(--card); white-space:nowrap; } td.n { font-variant-numeric:tabular-nums; white-space:nowrap; }
td.addr { word-break:break-all; color:var(--dim); }
.s-proven,.s-answers { color:var(--ok); } .s-blocked { color:var(--warn); }
.s-dead,.s-broken { color:var(--bad); }
button { font:inherit; padding:6px 12px; border-radius:6px; border:1px solid var(--line);
         background:var(--card); color:var(--fg); cursor:pointer; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:4px 16px; margin:8px 0; }
dt { font-weight:600; } dd { margin:0; color:var(--dim); }
@media (max-width:560px) { dl { grid-template-columns:1fr; } dd { margin-bottom:8px; } }
</style>
</head>
<body>
<main>
<h1>Helix site status</h1>
<p class="dim">Every site Helix can scan, checked once a day. Last check: <span id="when"></span>.</p>
<div class="tiles" id="tiles"></div>
<p id="summary"></p>

<h2>What the states mean</h2>
<dl>
<dt class="s-proven">proven</dt><dd>A real account was found and a made-up name was not.</dd>
<dt class="s-answers">answers</dt><dd>A made-up name got a clear "no such user". No test account is listed for the site, or the listed one was not found.</dd>
<dt class="s-blocked">blocked</dt><dd>The site refused the checker's network (bot check, HTTP 401 or 403, rate limit). It may work from yours. Never switched off for this.</dd>
<dt class="s-dead">dead</dt><dd>The host name does not resolve, the certificate is invalid, the connection fails or times out, or the server answers 5xx.</dd>
<dt class="s-broken">broken</dt><dd>The rule reported an account for a made-up name, so it cannot tell names apart.</dd>
<dt>unknown</dt><dd>Anything else, such as a host the checker itself could not reach.</dd>
</dl>
<p class="dim">A site that is dead or broken on __OFF_AFTER__ checks in a row is switched off: scans leave it out and say how many sites they left out. The first check that finds it working switches it back on. The check runs from one network, so "dead" means dead from there. <code>--include-off</code> scans switched-off sites anyway.</p>

<h2>Sites</h2>
<div class="controls">
<input id="q" type="search" placeholder="Filter by name or address" aria-label="Filter by name or address">
<select id="state" aria-label="State"><option value="">All states</option></select>
<select id="source" aria-label="Source"><option value="">All sources</option></select>
</div>
<p class="dim" id="count"></p>
<div class="scroll"><table>
<thead><tr><th>Site</th><th>State</th><th>Why</th><th>Since (UTC)</th><th>Source</th><th>Profile address</th></tr></thead>
<tbody id="rows"></tbody>
</table></div>
<p><button id="more" type="button">Show more</button></p>

<h2>Recent checks</h2>
<div class="scroll"><table>
<thead><tr><th>Checked (UTC)</th><th>Sites</th><th>Proven</th><th>Answers</th><th>Blocked</th><th>Dead</th><th>Broken</th><th>Switched off</th><th>Helix</th></tr></thead>
<tbody id="runs"></tbody>
</table></div>
<p class="dim">Data: <a href="state.json">state.json</a> (every site) and <a href="switched_off.json">switched_off.json</a> (the list scans read). Made by <code>python -m helix_osint.health check</code> in the <a href="https://github.com/thalha-a9/helix">Helix</a> repository.</p>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById('data').textContent);
  var sites = data.sites, runs = data.runs, last = runs.length ? runs[runs.length - 1] : null;
  var states = ['proven', 'answers', 'blocked', 'dead', 'broken', 'unknown'];
  function el(tag, text, cls) { var e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
  function num(n) { return Number(n || 0).toLocaleString('en-US'); }
  document.getElementById('when').textContent = data.updated_utc ? data.updated_utc.replace('T', ' ').replace('+00:00', ' UTC') : 'never';
  var tiles = document.getElementById('tiles');
  function tile(label, value, cls) { var t = el('div', undefined, 'tile ' + cls); t.appendChild(el('b', num(value))); t.appendChild(el('span', label)); tiles.appendChild(t); }
  if (last) {
    tile('sites', last.sites, '');
    states.slice(0, 5).forEach(function (s) { tile(s, last[s], s); });
    tile('switched off', last.off, 'off');
    var working = (last.proven || 0) + (last.answers || 0), on = last.sites - last.off;
    document.getElementById('summary').textContent = num(working) + ' of the ' + num(on) + ' sites a scan checks (' +
      (on ? (100 * working / on).toFixed(1) : '0') + '%) answered this check. ' + num(last.off) + ' more are switched off.';
  }
  var stateSel = document.getElementById('state'), sourceSel = document.getElementById('source');
  states.concat(['off']).forEach(function (s) { var o = el('option', s === 'off' ? 'switched off' : s); o.value = s; stateSel.appendChild(o); });
  var sources = {}; sites.forEach(function (s) { sources[s[2]] = 1; });
  Object.keys(sources).sort().forEach(function (s) { var o = el('option', s); o.value = s; sourceSel.appendChild(o); });
  var shown = 200, q = document.getElementById('q'), rows = document.getElementById('rows');
  function draw() {
    var text = q.value.trim().toLowerCase(), st = stateSel.value, src = sourceSel.value;
    var hit = sites.filter(function (s) {
      if (st === 'off' ? !s[6] : (st && s[3] !== st)) return false;
      if (src && s[2] !== src) return false;
      return !text || s[0].toLowerCase().indexOf(text) >= 0 || s[1].indexOf(text) >= 0;
    });
    rows.textContent = '';
    hit.slice(0, shown).forEach(function (s) {
      var tr = el('tr');
      tr.appendChild(el('td', s[1]));
      tr.appendChild(el('td', s[3] + (s[6] ? ' (off)' : ''), 's-' + s[3]));
      tr.appendChild(el('td', s[4]));
      tr.appendChild(el('td', (s[5] || '').slice(0, 16).replace('T', ' '), 'n'));
      tr.appendChild(el('td', s[2]));
      tr.appendChild(el('td', s[0], 'addr'));
      rows.appendChild(tr);
    });
    document.getElementById('count').textContent = num(hit.length) + ' site' + (hit.length === 1 ? '' : 's') +
      (hit.length > shown ? ', first ' + num(shown) + ' shown' : '');
    document.getElementById('more').style.display = hit.length > shown ? '' : 'none';
  }
  [q, stateSel, sourceSel].forEach(function (c) { c.addEventListener('input', function () { shown = 200; draw(); }); });
  document.getElementById('more').addEventListener('click', function () { shown += 1000; draw(); });
  draw();
  var rt = document.getElementById('runs');
  runs.slice().reverse().slice(0, 30).forEach(function (r) {
    var tr = el('tr');
    [r.utc.slice(0, 16).replace('T', ' '), num(r.sites), num(r.proven), num(r.answers), num(r.blocked), num(r.dead), num(r.broken), num(r.off), r.helix]
      .forEach(function (v, i) { tr.appendChild(el('td', v, i ? 'n' : 'n')); });
    rt.appendChild(tr);
  });
})();
</script>
</body>
</html>
"""


def render_page(state: dict) -> str:
    """The status page: one self-contained HTML file. Site names and
    addresses come from other people's databases, so they travel as JSON and
    are written with textContent, never as markup."""
    sites = [[key, e.get("name", ""), e.get("source", ""), e.get("state", ""), e.get("why", ""),
              e.get("since", ""), 1 if e.get("off") else 0]
             for key, e in state.get("sites", {}).items()]
    order = {s: i for i, s in enumerate(("broken", "dead", "blocked", "unknown", "answers", "proven"))}
    sites.sort(key=lambda s: (order.get(s[3], 9), s[1].lower()))
    data = {"updated_utc": state.get("updated_utc", ""), "runs": state.get("runs", []), "sites": sites}
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    return (_PAGE.replace("__OFF_AFTER__", html.escape(str(OFF_AFTER)))
                 .replace("__DATA__", blob))


def write_outputs(state: dict, out_dir: str) -> Dict[str, str]:
    """Write switched_off.json and index.html next to the record."""
    os.makedirs(out_dir, exist_ok=True)
    paths = {"off": os.path.join(out_dir, "switched_off.json"),
             "page": os.path.join(out_dir, "index.html")}
    with open(paths["off"], "w", encoding="utf-8") as f:
        json.dump(switched_off(state), f, indent=1, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    with open(paths["page"], "w", encoding="utf-8") as f:
        f.write(render_page(state))
    return paths


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except FileNotFoundError:
        return new_state()
    if not isinstance(state, dict) or state.get("schema") != SCHEMA:
        raise ValueError(f"{path} is not a Helix site-health record")
    return state


def save_state(state: dict, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


# Command line

def _line(done: int, total: int, label: str) -> None:
    if done == total or done % 200 == 0:
        print(f"\r  {label} {done}/{total}", end="", flush=True)


async def _run_check(args) -> int:
    from helix_osint import sources
    flags, unknown = sources.source_flags(args.sources.split(","))
    if unknown:
        print(f"Unknown source(s): {', '.join(unknown)}. Use: all, {', '.join(sources.SOURCES)}")
        return 2
    state = load_state(args.state)
    platform_map = await sources.load(nsfw=args.nsfw, **flags)
    if args.limit:
        platform_map = dict(list(platform_map.items())[:args.limit])
    print(f"  Checking {len(platform_map)} sites...")
    started = time.time()
    seen = await check(platform_map, concurrency=args.concurrency,
                       progress_cb=lambda d, t: _line(d, t, "made-up name:"),
                       known_cb=lambda d, t: _line(d, t, "listed accounts:"))
    print()
    state = update(state, seen, utc_now(), time.time() - started,
                   min_gap_hours=args.min_gap_hours, where=args.where)
    save_state(state, args.state)
    paths = write_outputs(state, args.out or os.path.dirname(os.path.abspath(args.state)))
    run = state["runs"][-1]
    print("  " + "  ".join(f"{s} {run[s]}" for s in STATES) + f"  switched off {run['off']}")
    if not run["counted"]:
        print(f"  The last counted check was under {args.min_gap_hours:g} h ago: "
              f"this one updated the states but not the failure counts.")
    print(f"  Record {args.state}\n  List   {paths['off']}\n  Page   {paths['page']}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m helix_osint.health", description="The daily site check.")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check every site and update the record")
    c.add_argument("--state", required=True, help="the record file (created if missing)")
    c.add_argument("--out", default=None, help="folder for switched_off.json and index.html "
                                               "(default: next to the record)")
    c.add_argument("--sources", default="all", help="all, or a comma list of wmn, sherlock, maigret, fediverse")
    c.add_argument("--nsfw", action="store_true", help="include adult sites")
    c.add_argument("--concurrency", type=int, default=None)
    c.add_argument("--min-gap-hours", type=float, default=MIN_GAP_HOURS, dest="min_gap_hours",
                   help=f"checks closer together than this count as one (default {MIN_GAP_HOURS})")
    c.add_argument("--where", default="", help="a note on where the check ran, shown in the record")
    c.add_argument("--limit", type=int, default=0, help="check only the first N sites (for a trial)")
    g = sub.add_parser("page", help="rebuild switched_off.json and index.html from the record")
    g.add_argument("--state", required=True)
    g.add_argument("--out", default=None)
    args = p.parse_args(argv)
    if args.cmd == "check":
        return asyncio.run(_run_check(args))
    state = load_state(args.state)
    paths = write_outputs(state, args.out or os.path.dirname(os.path.abspath(args.state)))
    print(f"List {paths['off']}\nPage {paths['page']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
