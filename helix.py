#!/usr/bin/env python3
"""
Helix — OSINT Identity Mapper v3.0
Author : Thalha Ahmed (@thalha-a9)
Repo   : github.com/thalha-a9/helix

Verification stack (runs in order on every scan):
  1. Local heuristic verifier  — always on, zero dependencies
  2. AI verifier (--ai)        — optional, multi-provider (claude/openrouter/nvidia)
"""

import asyncio, argparse, os, sys, time, webbrowser
from datetime import datetime

def _check_deps():
    try: import aiohttp
    except ImportError:
        print("\n[!] Missing: aiohttp  →  pip install -r requirements.txt\n"); sys.exit(1)

from osint              import netconfig
from osint.checker      import check_username, check_email, validate_username, validate_email, HAS_CURL_CFFI
from osint.location     import annotate_locations, flag_conflicts, describe_subject_location
from osint.graph        import generate_graph
from osint.report       import save_json, save_csv, save_txt
from osint.platforms    import PLATFORMS, CATEGORY_META
from osint.permutations import generate_permutations
from osint.verifier     import run_local_verifier
from osint.phash        import HAS_PHASH, hash_all_avatars, find_matches
from osint.email_permutations import generate_email_permutations
from osint.pdf_report   import generate_pdf_report, HAS_WEASYPRINT

G="\033[92m"; Y="\033[93m"; C="\033[96m"; M="\033[95m"; R="\033[91m"
DIM="\033[2m"; B="\033[1m"; RST="\033[0m"

BANNER = f"""{C}{B}
  ██╗  ██╗███████╗██╗     ██╗██╗  ██╗
  ██║  ██║██╔════╝██║     ██║╚██╗██╔╝
  ███████║█████╗  ██║     ██║ ╚███╔╝
  ██╔══██║██╔══╝  ██║     ██║ ██╔██╗
  ██║  ██║███████╗███████╗██║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝{RST}
  {DIM}Decode the digital DNA of any identity{RST}
  {DIM}v3.4 · @thalha-a9 · github.com/thalha-a9/helix{RST}
"""

def banner():
    print(BANNER)
    feats = []
    feats.append(f"{G}curl_cffi{RST}"   if HAS_CURL_CFFI else f"{DIM}aiohttp{RST}")
    feats.append(f"{G}pHash{RST}"       if HAS_PHASH    else f"{DIM}pHash[pip install imagehash Pillow]{RST}")
    feats.append(f"{G}local verifier{RST}")
    print(f"  {DIM}Engine:{RST} {' · '.join(feats)}\n")


class Progress:
    def __init__(self, total):
        self.total=total; self.start=time.time()
    def update(self, done, total):
        pct  = int((done/total)*38)
        bar  = f"{G}{'█'*pct}{DIM}{'░'*(38-pct)}{RST}"
        el   = time.time()-self.start
        rate = done/el if el>0 else 0
        eta  = int((total-done)/rate) if rate>0 else 0
        print(f"\r  {bar} {C}{done}/{total}{RST} "
              f"{DIM}{rate:.1f}/s eta:{eta}s   {RST}", end="", flush=True)
    def finish(self): print()


def _sanitize(results: list) -> list:
    defaults = {
        "platform":"","url":"","category":"other","color":"#94a3b8",
        "found":False,"error":None,"confidence":"low","bio_links":{},
        "target_type":"username","source":"builtin","status_code":None,
        "og_title":"","avatar_url":"","phash":"","final_url":"",
        "location_hints":[],"location_countries":[],
        "location_conflict":False,"location_note":"",
    }
    safe = []
    for r in results:
        entry = {**defaults, **r}
        entry.pop("_page_text", None)  # internal only — never written to reports
        for k in ("platform","url","category","error","og_title","final_url"):
            if entry[k] is not None:
                entry[k] = str(entry[k]).encode("utf-8","replace").decode("utf-8")
        safe.append(entry)
    return safe


def _print_found(found, note=""):
    if not found: print(f"  {DIM}None found.{RST}"); return
    if note: print(f"  {DIM}{note}{RST}")
    cur_cat = None
    for r in sorted(found, key=lambda x: x["category"]):
        if r["category"] != cur_cat:
            cur_cat = r["category"]
            lbl = CATEGORY_META.get(cur_cat,{}).get("label",cur_cat).upper()
            print(f"  {DIM}── {lbl} {'─'*(44-len(lbl))}{RST}")
        cf  = f" {G}●{RST}" if r.get("confidence")=="high" else ""
        xl  = f" {C}↔{RST}" if r.get("bio_links")          else ""
        ph  = f" {M}≅{RST}" if r.get("phash")              else ""
        src = {"sherlock":f" {DIM}[S]{RST}","wmn":f" {DIM}[W]{RST}",
               "holehe":f" {M}[H]{RST}"}.get(r.get("source",""),"")
        lc  = f" {R}⚑ location conflict{RST}" if r.get("location_conflict") else ""
        print(f"  {G}[+]{RST} {r['platform']:<24}{DIM}{r['url']}{RST}{cf}{xl}{ph}{src}{lc}")


async def run(args):
    banner()

    if args.providers:
        from osint.adapters.ai_verifier import provider_status
        print(f"\n  {C}AI Providers:{RST}\n{provider_status()}\n"); return

    username = args.username.strip().lstrip("@") if args.username else None
    email    = args.email.strip()               if args.email    else None

    if not username and not email:
        print(f"{R}[!] Provide -u username and/or -e email{RST}\n"); sys.exit(1)
    if username:
        ok, msg = validate_username(username)
        if not ok: print(f"{R}[!] {msg}{RST}\n"); sys.exit(1)
    if email:
        ok, msg = validate_email(email)
        if not ok: print(f"{R}[!] {msg}{RST}\n"); sys.exit(1)

    platform_map = dict(PLATFORMS)

    # ── WhatsMyName ───────────────────────────────────────────────────────────
    if args.wmn:
        print(f"  {C}[*]{RST} Fetching WhatsMyName database…")
        from osint.adapters.wmn_adapter import load_with_fallback as wmn_load
        wmn  = await wmn_load(timeout=args.wmn_timeout, include_nsfw=getattr(args,"nsfw",False))
        added = sum(1 for k in wmn if k not in platform_map)
        platform_map.update({k:v for k,v in wmn.items() if k not in platform_map})
        print(f"  {G}[+]{RST} WhatsMyName: +{added} → total {len(platform_map)}\n")

    # ── Sherlock ──────────────────────────────────────────────────────────────
    if args.sherlock:
        print(f"  {C}[*]{RST} Fetching Sherlock database…")
        from osint.adapters.sherlock_adapter import load_with_fallback as sh_load
        sh   = await sh_load(timeout=args.sherlock_timeout)
        added = sum(1 for k in sh if k not in platform_map)
        platform_map.update({k:v for k,v in sh.items() if k not in platform_map})
        print(f"  {G}[+]{RST} Sherlock: +{added} → total {len(platform_map)}\n")

    # ── Maigret ───────────────────────────────────────────────────────────────
    if args.maigret:
        print(f"  {C}[*]{RST} Fetching Maigret database…")
        from osint.adapters.maigret_adapter import load_with_fallback as mg_load
        mg   = await mg_load(timeout=args.maigret_timeout, include_nsfw=getattr(args,"nsfw",False))
        added = sum(1 for k in mg if k not in platform_map)
        platform_map.update({k:v for k,v in mg.items() if k not in platform_map})
        print(f"  {G}[+]{RST} Maigret: +{added} → total {len(platform_map)}\n")

    # Strip leading dots/underscores so output dir isn't hidden on Linux
    # e.g. .rxzikhx. → rxzikhx_ 
    _raw_label = username or email.replace("@","_at_").replace(".","_")
    label = _raw_label.lstrip("._") or _raw_label.replace(".","_").replace("-","_") or "scan"
    _raw_out = args.output or os.path.join("results", label)
    out = os.path.realpath(_raw_out)
    _cwd = os.path.realpath(os.getcwd())
    if args.output and not out.startswith(_cwd):
        print(f"{R}[!] --output path must be within current directory{RST}"); import sys; sys.exit(1)
    os.makedirs(out, exist_ok=True)

    targets = []
    if username: targets.append(f"{C}@{username}{RST}")
    if email:    targets.append(f"{M}{email}{RST}")
    print(f"  {DIM}Target   :{RST} {' + '.join(targets)}")
    print(f"  {DIM}Platforms:{RST} {len(platform_map)}")
    ver_str = f"{G}Local heuristics{RST}"
    if args.ai: ver_str += f" + {C}AI ({args.ai}){RST}"
    print(f"  {DIM}Verifier :{RST} {ver_str}")
    if args.location:
        print(f"  {DIM}Location :{RST} {C}{describe_subject_location(args.location)}{RST}")
    egress = netconfig.describe()
    if netconfig.get_proxy():
        print(f"  {DIM}Network  :{RST} {G}{egress}{RST}\n")
    else:
        print(f"  {DIM}Network  :{RST} {Y}{egress}{RST}")
        print(f"  {DIM}           every probed platform logs your IP — "
              f"use --tor or --proxy for real investigations{RST}\n")

    results=[];  email_results=[];  pivot_data={};  phash_matches=[]; loc_conflicts=[]
    wayback_data={}; crt_data={}; paste_data={}; github_intel={}

    # ── Username scan ─────────────────────────────────────────────────────────
    if username:
        if args.permutations:
            perms = generate_permutations(username)
            print(f"  {C}[*]{RST} {len(perms)} permutations available")
            try:   choice = input(f"  {DIM}Scan all? [y/N]: {RST}").strip().lower()
            except: choice = "n"
            if choice == "y":
                pall = {}
                for p in perms:
                    pg = Progress(len(platform_map))
                    pr = await check_username(p,platforms=platform_map,progress_cb=pg.update)
                    pg.finish()
                    pr = _sanitize(pr)
                    pr, _ = run_local_verifier(pr, p)
                    fp = [r for r in pr if r.get("found")]
                    if fp: pall[p]=fp; print(f"  {G}[+]{RST} {C}{p}{RST}: {len(fp)} profiles")
                if pall:
                    import json
                    pp = os.path.join(out, f"{label}_permutations.json")
                    with open(pp,"w",encoding="utf-8") as f:
                        json.dump({k:[r["url"] for r in v] for k,v in pall.items()},f,indent=2)
                    print(f"  {G}[+]{RST} Perms → {pp}\n")

        prog = Progress(len(platform_map))
        _scan_start = time.time()
        print(f"  {DIM}Scanning @{username} across {len(platform_map)} platforms…{RST}\n")
        raw_results = await check_username(username,platforms=platform_map,
                                           progress_cb=prog.update)
        # Runs before _sanitize strips the raw page text it reads from.
        annotate_locations(raw_results)
        results = _sanitize(raw_results)
        prog.finish()

        # ── Local heuristic verifier ─────────────────────────────────────────
        results, purge_log = run_local_verifier(results, username)
        if purge_log:
            print(f"\n  {Y}[heuristic]{RST} Purged {len(purge_log)} false positive(s):")
            for p in purge_log[:5]:
                print(f"  {DIM}  ✗ {p['platform']}: {p['reason'][:70]}{RST}")
            if len(purge_log) > 5:
                print(f"  {DIM}  … +{len(purge_log)-5} more{RST}")

        # ── AI verifier ───────────────────────────────────────────────────────
        if args.ai:
            from osint.adapters.ai_verifier import verify_with_ai, apply_verdict
            print(f"\n  {C}[*]{RST} AI verification ({args.ai})…")
            verdict = await verify_with_ai(results, provider=args.ai)
            if verdict.get("error"):
                print(f"  {Y}[!]{RST} AI error: {verdict['error']}")
            else:
                results = apply_verdict(results, verdict)
                ai_n    = len(verdict.get("purged",[]))
                print(f"  {G}[+]{RST} AI ({verdict.get('model','?')}): {ai_n} additional purged")

        # ── Location conflict check ───────────────────────────────────────────
        loc_conflicts = flag_conflicts(results, args.location) if args.location else []
        if loc_conflicts:
            print(f"\n  {R}{B}{'!'*54}{RST}")
            print(f"  {R}{B}  LOCATION CONFLICT — {len(loc_conflicts)} candidate(s) "
                  f"contradict the known subject location{RST}")
            print(f"  {R}{B}{'!'*54}{RST}")
            for c in loc_conflicts:
                print(f"  {R}[✗]{RST} {B}{c['platform']}{RST} {DIM}{c['url']}{RST}")
                print(f"      {Y}states{RST} {', '.join(c['stated'])}  "
                      f"{DIM}·{RST}  {Y}expected{RST} {', '.join(c['expected'])}")
                if c["hints"]:
                    print(f"      {DIM}evidence: {' | '.join(c['hints'][:3])}{RST}")
            print(f"  {DIM}  Verify these before confirming — a conflicting location "
                  f"often means a different person.{RST}\n")

        found_u  = [r for r in results if r.get("found")]
        xlinks   = sum(1 for r in found_u if r.get("bio_links"))

        # ── Real name extraction from OG-verified profiles ────────────────
        real_name = ""
        for r in found_u:
            og = r.get("og_title","") or ""
            if og and r.get("confidence") == "high":
                # Strip platform name suffixes like "- Dribbble", "| Poe"
                import re as _re
                clean = _re.sub(r'[|\-\u2013\u2014].*$','',og).strip()
                if clean and len(clean.split()) >= 2 and not any(
                    x in clean.lower() for x in ['http','www','.com',username.lower()]
                ):
                    real_name = clean
                    break
        if real_name:
            print(f"  {G}[+]{RST} Real name extracted: {C}{real_name}{RST}")
        elapsed  = time.time()-prog.start
        skipped  = sum(1 for r in results if "curl_cffi" in (r.get("error") or ""))

        print(f"\n  {B}{'─'*54}{RST}")
        print(f"  {G}{B}Found {len(found_u)}/{len(results)}{RST}  "
              f"{C}Cross-links {xlinks}{RST}  {DIM}Time {elapsed:.1f}s{RST}")
        if skipped:
            print(f"  {Y}[!]{RST} {DIM}{skipped} WAF platforms skipped — pip install curl-cffi{RST}")
        print(f"  {B}{'─'*54}{RST}")
        _print_found(found_u)
        print(f"\n  {G}●{RST}=OG-verified  {C}↔{RST}=bio  {DIM}[S]{RST}=Sherlock  {DIM}[W]{RST}=WMN  {DIM}[M]{RST}=Maigret  {M}≅{RST}=avatar\n")

        # ── Email permutation ────────────────────────────────────────────────────
        if args.email_permute and found_u:
            print(f"  {C}[*]{RST} Generating email permutations...")
            from osint.email_permutations import generate_email_permutations
            email_perms = generate_email_permutations(username, real_name)
            if email_perms:
                print(f"  {G}[+]{RST} {len(email_perms)} likely email(s) generated:")
                for ep in email_perms[:12]:
                    print(f"  {DIM}  {ep}{RST}")
                if args.holehe:
                    print(f"  {C}[*]{RST} Running holehe on top permutations...")
                    from osint.adapters.holehe_adapter import load_with_fallback as holehe_run
                    for ep in email_perms[:3]:
                        ep_res = _sanitize(await holehe_run(ep))
                        ep_found = [r for r in ep_res if r.get("found")]
                        if ep_found:
                            print(f"  {G}[+]{RST} {C}{ep}{RST}: found on {', '.join(r['platform'] for r in ep_found)}")
                            email_results.extend(ep_res)
            print()

        # ── pHash ─────────────────────────────────────────────────────────────
        if args.phash:
            if not HAS_PHASH:
                print(f"  {Y}[!]{RST} pip install imagehash Pillow\n")
            else:
                print(f"  {C}[*]{RST} Hashing avatars…")
                hashes = await hash_all_avatars(found_u)
                if hashes:
                    phash_matches = find_matches(hashes)
                    for r in results:
                        if r["platform"] in hashes: r["phash"]=hashes[r["platform"]]
                    if phash_matches:
                        print(f"  {G}[+]{RST} {M}Avatar matches:{RST}")
                        for m in phash_matches:
                            icon = "🎯" if m["match_type"]=="exact" else "~"
                            print(f"  {M}[≅]{RST} {icon} {m['platform_a']} ↔ {m['platform_b']}  "
                                  f"conf:{m['confidence']}")
                print()

        # ── Wayback Machine ───────────────────────────────────────────────────
        if args.wayback:
            print(f"  {C}[*]{RST} Checking Wayback Machine (Archive.org)…")
            from osint.modules.wayback import check_profiles as wb_check
            wayback_data = await wb_check(found_u)
            if wayback_data:
                print(f"  {G}[+]{RST} Wayback: {len(wayback_data)} profile(s) archived")
                for plat, wd in wayback_data.items():
                    clues = wd.get("identity_clues",[])
                    print(f"  {DIM}  {plat}: first seen {wd['first_seen']}"
                          f" · {wd['count']} snapshots"
                          + (f" · {len(clues)} clue(s)" if clues else "") + RST)
            print()

        # ── GitHub Deep Recon (auto-runs when GitHub found) ───────────────────
        github_r = next((r for r in found_u if r["platform"] == "GitHub"), None)
        if github_r:
            print(f"  {C}[*]{RST} GitHub deep recon for @{username}…")
            from osint.modules.github_deep import run as gh_run
            intel = await gh_run(username)
            github_intel = intel
            if intel.get("error"):
                print(f"  {Y}[!]{RST} {intel['error']}")
            else:
                if intel.get("emails"):
                    print(f"  {G}[+]{RST} GitHub emails: {', '.join(intel['emails'])}")
                if intel.get("orgs"):
                    orgs = ', '.join(o['name'] for o in intel['orgs'])
                    print(f"  {G}[+]{RST} Orgs: {orgs}")
                if intel.get("timezone",{}).get("timezone") not in ("","insufficient data",None):
                    tz = intel["timezone"]
                    print(f"  {G}[+]{RST} Timezone: {tz['timezone']} "
                          f"(conf: {tz.get('confidence','?')}, "
                          f"peak: {tz.get('peak_hour','?')})")
                if intel.get("npm_packages"):
                    pkgs = ', '.join(p['name'] for p in intel['npm_packages'])
                    print(f"  {G}[+]{RST} npm packages: {pkgs}")
            print()

        # ── Certificate Transparency ──────────────────────────────────────────
        if args.crt:
            print(f"  {C}[*]{RST} Certificate transparency (crt.sh)…")
            from osint.modules.crt import run as crt_run
            crt_data = await crt_run(username, email)
            domains  = crt_data.get("all_domains",[])
            if domains:
                print(f"  {G}[+]{RST} CRT: {len(domains)} domain(s) found")
                for d in domains[:8]:
                    print(f"  {DIM}  {d}{RST}")
                if len(domains) > 8:
                    print(f"  {DIM}  … +{len(domains)-8} more{RST}")
            else:
                print(f"  {DIM}  No domains found in CT logs{RST}")
            print()

        # ── Paste Intelligence ────────────────────────────────────────────────
        if args.paste:
            print(f"  {C}[*]{RST} Paste intelligence (Gist + Pastebin)…")
            from osint.modules.paste import run as paste_run
            paste_data = await paste_run(username, email)
            total = paste_data.get("total",0)
            if total:
                print(f"  {G}[+]{RST} Paste: {total} result(s)")
                for g in paste_data.get("gists",[])[:3]:
                    print(f"  {DIM}  [gist] {g['description'][:50]} — {g['url']}{RST}")
                for p in paste_data.get("username_pastes",[])[:3]:
                    print(f"  {DIM}  [paste] {p['url']}{RST}")
            else:
                print(f"  {DIM}  No mentions found{RST}")
            print()

        # ── Pivot ─────────────────────────────────────────────────────────────
        if args.pivot:
            from osint.pivot import pivot_scan
            depth = min(args.pivot_depth, 4)
            print(f"  {C}[*]{RST} Recursive pivot (depth {depth})…")
            def pcb(alias, d, n):
                print(f"  {G}[↻]{RST} @{alias} depth={d} → {n} profiles")
            pivot_data = await pivot_scan(username,results,platform_map,depth,pcb)
            if pivot_data:
                for alias, pd in pivot_data.items():
                    print(f"\n  {C}@{alias}{RST} {DIM}(depth {pd['depth']}, via {pd['discovered_via']}){RST}")
                    _print_found(pd["found"])
            print()

    # ── Email scan ────────────────────────────────────────────────────────────
    if email:
        if args.holehe:
            print(f"  {C}[*]{RST} holehe deep email scan…")
            from osint.adapters.holehe_adapter import load_with_fallback as holehe_run
            pg = Progress(120)
            email_results = _sanitize(await holehe_run(email, progress_cb=pg.update))
            pg.finish()
        else:
            print(f"  {DIM}Email scan: Gravatar only without --holehe{RST}")
            email_results = _sanitize(await check_email(email))

        ef = [r for r in email_results if r.get("found")]
        print(f"  {G}[+]{RST} Email: {len(ef)} profile(s) found")
        for r in ef:
            print(f"  {M}[e]{RST} {r['platform']:<24}{DIM}{r['url']}{RST}")
        if not args.holehe:
            print(f"  {Y}[tip]{RST} {DIM}--holehe checks 120+ platforms by email{RST}")
        print()

        if args.breach:
            print(f"  {C}[*]{RST} Checking breach databases for {email}…")
            from osint.adapters.breach_adapter import check_breaches, format_breach_report
            bd    = await check_breaches(email)
            lines = format_breach_report(bd)
            if bd.get("found"):
                print(f"  {R}[!]{RST} Found in {bd['count']} breach(es):")
            for line in lines: print(line)

    # ── PDF/HTML Report ──────────────────────────────────────────────────────
    if getattr(args,'report',False):
        _st = _scan_start if '_scan_start' in dir() else time.time()
        rp = generate_pdf_report(
            username=username or "", results=results, output_dir=out,
            email=email, email_results=email_results,
            wayback_data=wayback_data, github_intel=github_intel,
            crt_data=crt_data, paste_data=paste_data,
            phash_matches=phash_matches, pivot_data=pivot_data,
            scan_time=time.time()-_st,
        )
        print(f"  {G}[✓]{RST} {B}Report{RST}   → {rp['html']}")
        if rp.get('pdf'):
            print(f"  {G}[✓]{RST} {B}PDF{RST}      → {rp['pdf']}")
        elif not HAS_WEASYPRINT:
            print(f"  {Y}[!]{RST} {DIM}pip install weasyprint for PDF output{RST}")

    # ── Graph ─────────────────────────────────────────────────────────────────
    gpath = os.path.join(out, f"{label}_graph.html")
    generate_graph(
        username=username or "", results=results, output_path=gpath,
        email=email, email_results=email_results,
        pivot_data=pivot_data, phash_matches=phash_matches,
    )
    print(f"  {G}[✓]{RST} {B}Graph{RST}    → {gpath}")

    # ── Reports ───────────────────────────────────────────────────────────────
    all_r = results + email_results
    fmt   = args.format.lower()
    # Enrich JSON report with new intel
    intel_bundle = {
        "wayback":     wayback_data,
        "github_deep": github_intel,
        "crt":         {k: v for k, v in crt_data.items() if k != "all_domains"},
        "paste":       paste_data,
        "location":    {
            "subject":   args.location or "",
            "conflicts": loc_conflicts,
        },
    }
    if fmt in ("json","all"): print(f"  {G}[✓]{RST} JSON     → {save_json(label, all_r, out, extra=intel_bundle)}")
    if fmt in ("csv", "all"): print(f"  {G}[✓]{RST} CSV      → {save_csv(label, all_r, out)}")
    if fmt in ("txt", "all"): print(f"  {G}[✓]{RST} Text     → {save_txt(label, all_r, out)}")
    print()

    if not args.no_browser:
        webbrowser.open(f"file://{os.path.abspath(gpath)}")


def main():
    _check_deps()  # check at CLI entry, not import time
    p = argparse.ArgumentParser(
        prog="helix",
        description="Helix v3.4 — OSINT Identity Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
AI Providers (--ai):
  claude      Anthropic Claude  (ANTHROPIC_API_KEY)
  openrouter  Llama 3.1 free    (OPENROUTER_API_KEY — openrouter.ai)
  nvidia      Llama 3.1 free    (NVIDIA_API_KEY     — build.nvidia.com)

Examples:
  python helix.py -u johndoe
  python helix.py -u johndoe --wayback --crt --paste
  python helix.py -u johndoe --wmn --ai openrouter
  python helix.py -u johndoe --pivot --phash
  python helix.py -u johndoe -e email@x.com --breach --holehe
  python helix.py -u johndoe --wmn --sherlock --wayback --crt --paste --pivot --phash --format all
  python helix.py -u johndoe --report              # PDF/HTML investigation report
  python helix.py -u johndoe --email-permute       # generate likely emails + check with holehe

Operational security:
  python helix.py -u johndoe --tor                 # route every probe over local Tor
  python helix.py -u johndoe --proxy socks5://127.0.0.1:1080
  python helix.py -u johndoe --location "Wellington, New Zealand"
        """
    )
    p.add_argument("-u","--username",    default=None)
    p.add_argument("-e","--email",       default=None)
    p.add_argument("--providers",        action="store_true")

    g = p.add_argument_group("platform sources")
    g.add_argument("--wmn",             action="store_true")
    g.add_argument("--wmn-timeout",     type=int,default=30,  dest="wmn_timeout")
    g.add_argument("--sherlock",        action="store_true")
    g.add_argument("--sherlock-timeout",type=int,default=30,  dest="sherlock_timeout")
    g.add_argument("--maigret",         action="store_true",  help="Load Maigret database (github.com/soxoj/maigret)")
    g.add_argument("--maigret-timeout", type=int,default=30,  dest="maigret_timeout")

    g2 = p.add_argument_group("intelligence modules")
    g2.add_argument("--wayback",        action="store_true",  help="Wayback Machine — profile history + archived bios")
    g2.add_argument("--crt",            action="store_true",  help="Certificate Transparency — find owned domains")
    g2.add_argument("--paste",          action="store_true",  help="Paste Intelligence — Gists + Pastebin mentions")
    g2.add_argument("--breach",         action="store_true",  help="Email breach check")
    g2.add_argument("--holehe",         action="store_true",  help="Deep email scan via holehe (pip install holehe)")

    g3 = p.add_argument_group("advanced recon")
    g3.add_argument("--pivot",          action="store_true")
    g3.add_argument("--pivot-depth",    type=int,default=3,   dest="pivot_depth")
    g3.add_argument("--phash",          action="store_true")
    g3.add_argument("--permutations",   action="store_true")
    g3.add_argument("--ai",             default=None,
        type=lambda s: s.lower(),
        choices=["claude","openrouter","nvidia"],metavar="PROVIDER",
        help="AI false-positive filter: claude | openrouter | nvidia  (case-insensitive)")

    g4 = p.add_argument_group("operational security")
    g4.add_argument("--proxy", default=None, metavar="URL",
        help="Route every probe through a proxy "
             "(http://, https://, socks4://, socks5:// — socks needs aiohttp-socks)")
    g4.add_argument("--tor", action="store_true",
        help=f"Shorthand for --proxy {netconfig.TOR_PROXY} (local Tor SOCKS port)")
    g4.add_argument("--location", default=None, metavar="PLACE",
        help="Known subject location (e.g. \"Wellington, New Zealand\") — "
             "candidate profiles stating a conflicting location are flagged before confirmation")

    p.add_argument("--format",    default="json", choices=["json","csv","txt","all"])
    p.add_argument("--report",    action="store_true", help="Generate PDF/HTML investigation report")
    p.add_argument("--email-permute", action="store_true", dest="email_permute",
                   help="Generate likely email permutations from username + check with holehe")
    p.add_argument("--output",    default=None)
    p.add_argument("--no-browser",action="store_true", dest="no_browser")
    p.add_argument("--nsfw",      action="store_true", help="Include adult/NSFW platforms from WMN/Maigret (excluded by default)")
    p.add_argument("--version",   action="version", version="Helix v3.4.0")

    args = p.parse_args()
    args.pivot_depth = min(max(getattr(args,"pivot_depth",3),1),4)

    if args.tor and args.proxy:
        print(f"{R}[!] Use either --tor or --proxy, not both{RST}\n"); sys.exit(1)
    try:
        netconfig.set_proxy(netconfig.TOR_PROXY if args.tor else args.proxy)
    except ValueError as e:
        print(f"{R}[!] {e}{RST}\n"); sys.exit(1)

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print(f"\n\n  {Y}[!] Interrupted.{RST}\n"); sys.exit(0)

if __name__=="__main__":
    main()
