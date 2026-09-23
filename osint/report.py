"""Helix — Report Generator (JSON, CSV, TXT)"""
import json, csv, os
from datetime import datetime

def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def save_json(username: str, results: list, output_dir: str, extra: dict = None) -> str:
    found  = [r for r in results if r.get("found")]
    errors = [r for r in results if r.get("error")]
    report = {
        "tool":      "Helix",
        "version":   "3.1.0",
        "author":    "github.com/thalha-a9/helix",
        "timestamp": datetime.now().isoformat(),
        "target":    username,
        "summary":   {
            "total_checked": len(results),
            "found":         len(found),
            "not_found":     len(results) - len(found) - len(errors),
            "errors":        len(errors),
        },
        "found":   found,
        "errors":  errors,
        "intel":   extra or {},
    }
    path = os.path.join(output_dir, f"{username}_{_ts()}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return path

def save_csv(username: str, results: list, output_dir: str) -> str:
    path   = os.path.join(output_dir, f"{username}_{_ts()}.csv")
    fields = ["platform","found","url","category","confidence","identity_confidence",
              "evidence","source","error","status_code"]
    rows = [{**r, "evidence": "; ".join(r.get("evidence") or [])} for r in results]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)
    return path

def save_txt(username: str, results: list, output_dir: str) -> str:
    found  = sorted([r for r in results if r.get("found")], key=lambda x: x["category"])
    errors = [r for r in results if r.get("error")]
    ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines  = [
        "="*60, f"  Helix v3.1 — @{username}", f"  {ts}", "="*60, "",
        f"  Found  : {len(found)}/{len(results)}",
        f"  Errors : {len(errors)}", "", "-"*60, "  FOUND PROFILES", "-"*60,
    ]
    cur_cat = None
    for r in found:
        if r["category"] != cur_cat:
            cur_cat = r["category"]
            lines.append(f"\n  [{cur_cat.upper()}]")
        cf = " ●" if r.get("confidence")=="high" else ""
        ic = f"[{r['identity_confidence']}] " if r.get("identity_confidence") else ""
        lines.append(f"  [+] {ic}{r['platform']:<22} {r['url']}{cf}")
        if r.get("evidence"):
            lines.append(f"        evidence: {'; '.join(r['evidence'])}")
    if errors:
        lines += ["", "-"*60, "  ERRORS", "-"*60]
        for r in errors:
            lines.append(f"  [!] {r['platform']:<22} {(r.get('error') or '')[:60]}")
    lines += ["", "="*60, ""]
    path = os.path.join(output_dir, f"{username}_{_ts()}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path
