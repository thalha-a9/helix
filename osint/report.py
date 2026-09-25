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

def intel_rows(extra: dict) -> list:
    """Breach, dark-web and relationship findings as CSV rows (same columns)."""
    extra = extra or {}
    rows = []
    for v in extra.get("breaches") or []:
        if not v.get("breaches"):
            rows.append({"platform": f"Breach check: {v['identifier']}", "found": v.get("exposed"),
                         "category": "breach", "evidence": v["summary"],
                         "source": ", ".join(s["source"] for s in v["sources"])})
        for b in v.get("breaches") or []:
            rows.append({"platform": f"Breach: {b['name']}", "found": True, "category": "breach",
                         "confidence": "lead",
                         "evidence": f"{v['identifier']}; {b['date']}; exposed: "
                                     f"{', '.join(b['data_classes'])}",
                         "source": ", ".join(b["sources"])})
    for blk in (extra.get("darkweb") or {}).get("ahmia") or []:
        for h in blk.get("hits") or []:
            rows.append({"platform": f"Onion: {h['onion']}", "found": True, "url": h["url"],
                         "category": "darkweb", "confidence": "lead",
                         "evidence": f"mentions '{h['term']}'; {h['title']}", "source": "Ahmia"})
    for e in extra.get("relationships") or []:
        rows.append({"platform": f"Relationship: {e['relation']} → {e['target']}", "found": True,
                     "category": "relationship", "identity_confidence": e["confidence"],
                     "url": e["sources"][0]["url"] if e["sources"] else "",
                     "evidence": "; ".join(f"{s['platform']}: {s['method']} — \"{s['quote']}\""
                                           for s in e["sources"]),
                     "source": "declared"})
    return rows


def save_csv(username: str, results: list, output_dir: str, extra: dict = None) -> str:
    path   = os.path.join(output_dir, f"{username}_{_ts()}.csv")
    fields = ["platform","found","url","category","confidence","identity_confidence",
              "evidence","source","error","status_code"]
    rows = [{**r, "evidence": "; ".join(r.get("evidence") or [])} for r in results]
    rows += intel_rows(extra)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)
    return path

def intel_lines(extra: dict) -> list:
    extra = extra or {}
    lines = []
    rels = extra.get("relationships") or []
    if rels:
        from osint.relationships import edge_line
        lines += ["", "-"*60, "  RELATIONSHIPS (declared by the subject's accounts)", "-"*60]
        for e in rels:
            lines.append(f"  {edge_line(e)}")
            for s in e["sources"]:
                lines.append(f"        \"{s['quote']}\" — {s['url']}")
    verdicts = extra.get("breaches") or []
    if verdicts:
        from osint.adapters.breachdb import format_lines
        lines += ["", "-"*60, "  BREACH EXPOSURE (leads — exposure, not identity)", "-"*60]
        for v in verdicts:
            lines += [f"  {l}" for l in format_lines(v)]
    dw = extra.get("darkweb") or {}
    if dw.get("ahmia"):
        lines += ["", "-"*60, "  DARK-WEB LEADS (Ahmia) — unverified", "-"*60]
        for blk in dw["ahmia"]:
            if blk["status"] != "ok":
                lines.append(f"  '{blk['term']}': not checked — {blk['detail']}")
                continue
            lines.append(f"  '{blk['term']}': {len(blk['hits'])} lead(s)")
            for h in blk["hits"]:
                lines.append(f"    {h['url']}  {h['title'][:70]}")
        an = dw.get("analysis") or {}
        for f in an.get("findings") or []:
            lines.append(f"  [AI {f['confidence']}] {f['statement']} [{', '.join(f['sources'])}]")
    return lines


def save_txt(username: str, results: list, output_dir: str, extra: dict = None) -> str:
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
    lines += intel_lines(extra)
    lines += ["", "="*60, ""]
    path = os.path.join(output_dir, f"{username}_{_ts()}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path
