import html as _html_esc
"""
Helix v3 — PDF Investigation Report Generator
Generates a clean, shareable PDF report using weasyprint (optional)
or falls back to a standalone HTML report if weasyprint not installed.
"""
import os, json
from datetime import datetime
from typing import List, Dict, Optional

try:
    from weasyprint import HTML as WP_HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


def _confidence_badge(conf: str) -> str:
    colors = {"high": "#00ff88", "medium": "#60a5fa", "low": "#4b5563"}
    c = colors.get(conf, "#4b5563")
    return f'<span style="background:{c}22;color:{c};border:1px solid {c}55;border-radius:3px;padding:1px 6px;font-size:10px">{conf}</span>'


def _identity_cell(r: Dict) -> str:
    grade = r.get("identity_confidence") or ""
    if not grade:
        return '<span style="color:#4b5563;font-size:10px">—</span>'
    c = {"HIGH": "#00ff88", "MEDIUM": "#60a5fa", "LOW": "#6b7280"}.get(grade, "#6b7280")
    badge = (f'<span style="background:{c}22;color:{c};border:1px solid {c}55;'
             f'border-radius:3px;padding:1px 6px;font-size:10px;font-weight:600">{grade}</span>')
    ev = "<br>".join(_html_esc.escape(str(e)) for e in (r.get("evidence") or []))
    return f'{badge}<br><span style="color:#9ca3af;font-size:9px">{ev}</span>' if ev else badge


def _source_badge(src: str) -> str:
    colors = {"builtin": "#a78bfa", "wmn": "#38bdf8", "sherlock": "#fb923c", "maigret": "#f472b6"}
    c = colors.get(src, "#6b7280")
    return f'<span style="background:{c}22;color:{c};border:1px solid {c}44;border-radius:3px;padding:1px 6px;font-size:10px">{src}</span>'


_E = _html_esc.escape
_GRADE_C = {"HIGH": "#00ff88", "MEDIUM": "#60a5fa", "LOW": "#6b7280"}


def _grade(g: str) -> str:
    c = _GRADE_C.get(g, "#6b7280")
    return (f'<span style="background:{c}22;color:{c};border:1px solid {c}55;border-radius:3px;'
            f'padding:1px 6px;font-size:10px;font-weight:600">{_E(g)}</span>')


def _relationships_section(edges: List[Dict]) -> str:
    if not edges:
        return ""
    from osint.relationships import edge_line
    rows = ""
    for e in edges:
        quotes = "<br>".join(
            f'{_E(s["platform"])}: <i>&ldquo;{_E(s["quote"])}&rdquo;</i> '
            f'<span style="color:#6b7280">({_E(s["method"])})</span>' for s in e["sources"])
        rows += (f'<tr><td style="padding:6px 12px">{_grade(e["confidence"])}</td>'
                 f'<td style="padding:6px 12px;color:#e5e7eb">{_E(e["relation"].replace("_", " "))}</td>'
                 f'<td style="padding:6px 12px;color:#fbbf24">{_E(e["target"])}</td>'
                 f'<td style="padding:6px 12px;font-size:10px;color:#9ca3af">{quotes}</td></tr>\n')
    plain = "<br>".join(_E(edge_line(e)) for e in edges)
    return f"""
<div class="section">
  <div class="section-title">↔ Relationships ({len(edges)}) — declared by the subject's accounts, never inferred</div>
  <table class="data-table"><tr><th>Confidence</th><th>Relation</th><th>Target</th><th>Evidence</th></tr>{rows}</table>
  <div style="font-family:monospace;font-size:10px;color:#6b7280;margin-top:10px;line-height:1.7">{plain}</div>
</div>"""


def _breach_section(verdicts: List[Dict]) -> str:
    if not verdicts:
        return ""
    body = ""
    for v in verdicts:
        colour = "#f87171" if v.get("exposed") else ("#00ff88" if v.get("exposed") is False else "#fbbf24")
        body += f'<div class="intel-item" style="color:{colour}"><b>{_E(v["summary"])}</b></div>'
        for b in v.get("breaches") or []:
            body += (f'<div class="intel-item" style="padding-left:16px">{_E(b["name"])} '
                     f'<span style="color:#6b7280">({_E(b["date"] or "date unknown")})</span> — '
                     f'{_E(", ".join(b["data_classes"]))} '
                     f'<span style="color:#6b7280">via {_E(", ".join(b["sources"]))}</span></div>')
        checked = "; ".join(f'{s["source"]}: {s["status"]}{" — " + s["detail"] if s["detail"] else ""}'
                            for s in v["sources"])
        body += (f'<div class="intel-item" style="padding-left:16px;color:#6b7280;font-size:10px">'
                 f'checked {_E(v["checked_at"])} · {_E(checked)}</div>')
    return f"""
<div class="section">
  <div class="section-title">⚠ Breach Exposure — leads: exposure confirms a leak, not identity</div>
  {body}
</div>"""


def _darkweb_section(dw: Dict) -> str:
    blocks = dw.get("ahmia") or []
    if not blocks:
        return ""
    body = ""
    for blk in blocks:
        if blk["status"] != "ok":
            body += (f'<div class="intel-item" style="color:#fbbf24">&lsquo;{_E(blk["term"])}&rsquo;: '
                     f'not checked — {_E(blk["detail"])}</div>')
            continue
        body += (f'<div class="intel-item"><b>&lsquo;{_E(blk["term"])}&rsquo;</b>: '
                 f'{len(blk["hits"])} lead(s)</div>')
        for h in blk["hits"]:
            body += (f'<div class="intel-item" style="padding-left:16px;font-size:10px">'
                     f'<span style="color:#a78bfa">{_E(h["onion"])}</span> {_E(h["title"])}'
                     f'{" · seen " + _E(h["last_seen"]) if h["last_seen"] else ""}</div>')
    an = dw.get("analysis") or {}
    for f in an.get("findings") or []:
        body += (f'<div class="intel-item">{_grade(f["confidence"])} {_E(f["statement"])} '
                 f'<span style="color:#6b7280">[{_E(", ".join(f["sources"]))}]</span></div>')
    return f"""
<div class="section">
  <div class="section-title">☍ Dark-Web Leads (Ahmia) — unverified</div>
  {body}
</div>"""


def _build_html(username: str, results: List[Dict],
                email: str = "", email_results: List[Dict] = None,
                wayback_data: Dict = None, github_intel: Dict = None,
                crt_data: Dict = None, paste_data: Dict = None,
                phash_matches: List[Dict] = None,
                pivot_data: Dict = None,
                breach_verdicts: List[Dict] = None,
                darkweb: Dict = None,
                relationships: List[Dict] = None,
                scan_time: float = 0) -> str:

    found      = [r for r in results if r.get("found")]
    not_found  = [r for r in results if not r.get("found")]
    high_conf  = [r for r in found if r.get("confidence") == "high"]
    med_conf   = [r for r in found if r.get("confidence") == "medium"]
    low_conf   = [r for r in found if r.get("confidence") == "low"]
    ts         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Category grouping
    by_cat: Dict[str, List] = {}
    for r in found:
        by_cat.setdefault(r.get("category","other"), []).append(r)

    # Build found table rows
    rows = ""
    for cat, items in sorted(by_cat.items()):
        rows += f'<tr><td colspan="5" style="background:#111827;color:#6b7280;font-size:10px;padding:6px 12px;letter-spacing:2px;text-transform:uppercase">{cat}</td></tr>\n'
        for r in items:
            _og = _html_esc.escape(str(r.get('og_title','') or '')[:60])
            og = f'<br><span style="color:#a78bfa;font-size:10px;font-style:italic">{_og}</span>' if _og else ""
            _pn=_html_esc.escape(str(r['platform'])); _pu=_html_esc.escape(str(r['url']))
            rows += f"""<tr>
<td style="padding:8px 12px;font-weight:500;color:#e5e7eb">{_pn}</td>
<td style="padding:8px 12px">{_confidence_badge(r.get('confidence','low'))}</td>
<td style="padding:8px 12px">{_identity_cell(r)}</td>
<td style="padding:8px 12px">{_source_badge(r.get('source','builtin'))}</td>
<td style="padding:8px 12px;font-size:10px;color:#60a5fa;word-break:break-all"><a href="{_pu}" style="color:#60a5fa">{_pu}</a>{og}</td>
</tr>\n"""

    # Wayback section
    wb_section = ""
    if wayback_data:
        wb_rows = ""
        for plat, wd in wayback_data.items():
            wb_rows += f'<tr><td style="padding:6px 12px;color:#e5e7eb">{plat}</td><td style="padding:6px 12px;color:#00ff88">{wd.get("first_seen","?")}</td><td style="padding:6px 12px;color:#6b7280">{wd.get("last_seen","?")}</td><td style="padding:6px 12px;color:#60a5fa">{wd.get("count",0)} snapshots</td></tr>\n'
        if wb_rows:
            wb_section = f"""
<div class="section">
  <div class="section-title">⏱ Wayback Machine</div>
  <table class="data-table"><tr><th>Platform</th><th>First Seen</th><th>Last Seen</th><th>Snapshots</th></tr>{wb_rows}</table>
</div>"""

    # GitHub intel section
    gh_section = ""
    if github_intel and not github_intel.get("error"):
        gh_items = ""
        if github_intel.get("emails"):
            gh_items += f'<div class="intel-item"><span class="intel-label">Extracted emails:</span> {_html_esc.escape(", ".join(github_intel["emails"]))}</div>'
        if github_intel.get("orgs"):
            gh_items += f'<div class="intel-item"><span class="intel-label">Organizations:</span> {_html_esc.escape(", ".join(o["name"] for o in github_intel["orgs"]))}</div>'
        if github_intel.get("timezone",{}).get("timezone"):
            tz = github_intel["timezone"]
            gh_items += f'<div class="intel-item"><span class="intel-label">Inferred timezone:</span> {tz["timezone"]} (conf: {tz.get("confidence","?")})</div>'
        if github_intel.get("npm_packages"):
            gh_items += f'<div class="intel-item"><span class="intel-label">npm packages:</span> {", ".join(p["name"] for p in github_intel["npm_packages"])}</div>'
        if gh_items:
            gh_section = f'<div class="section"><div class="section-title">⚙ GitHub Deep Recon</div>{gh_items}</div>'

    # pHash section
    ph_section = ""
    if phash_matches:
        ph_rows = ""
        for m in phash_matches[:20]:
            icon = "🎯" if m.get("match_type") == "exact" else "~"
            ph_rows += f'<div class="intel-item">{icon} <strong>{m["platform_a"]}</strong> ↔ <strong>{m["platform_b"]}</strong> — {m.get("confidence","?")}</div>'
        ph_section = f'<div class="section"><div class="section-title">🖼 Avatar Hash Matches</div>{ph_rows}</div>'

    # CRT section
    crt_section = ""
    if crt_data and crt_data.get("all_domains"):
        domains = crt_data["all_domains"][:20]
        crt_section = f'<div class="section"><div class="section-title">🔐 Certificate Transparency ({len(domains)} domains)</div><div style="font-family:monospace;font-size:11px;color:#60a5fa;line-height:1.8">{"<br>".join(_html_esc.escape(d) for d in domains)}</div></div>'

    rel_section = _relationships_section(relationships or [])
    breach_section = _breach_section(breach_verdicts or [])
    dw_section = _darkweb_section(darkweb or {})

    email_line = f'<div class="meta-item"><span class="meta-label">Email:</span> {email}</div>' if email else ""

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Helix Report — {username}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0a0f; color: #c8d3e0; font-family: 'Courier New', monospace; font-size: 12px; padding: 32px; }}
  .header {{ border-bottom: 2px solid #00ff88; padding-bottom: 20px; margin-bottom: 28px; display: flex; justify-content: space-between; align-items: flex-end; }}
  .logo {{ font-size: 22px; font-weight: bold; color: #00ff88; letter-spacing: 4px; }}
  .subtitle {{ font-size: 10px; color: #4b5563; letter-spacing: 2px; margin-top: 4px; }}
  .header-right {{ text-align: right; font-size: 10px; color: #4b5563; line-height: 1.8; }}
  .stats-row {{ display: flex; gap: 16px; margin-bottom: 28px; }}
  .stat-box {{ flex: 1; background: #111827; border: 1px solid #1f2937; border-radius: 4px; padding: 16px; text-align: center; }}
  .stat-num {{ font-size: 28px; font-weight: bold; line-height: 1; }}
  .stat-label {{ font-size: 9px; color: #4b5563; letter-spacing: 1px; text-transform: uppercase; margin-top: 4px; }}
  .green {{ color: #00ff88; }} .blue {{ color: #60a5fa; }} .amber {{ color: #f59e0b; }} .pink {{ color: #f472b6; }}
  .section {{ margin-bottom: 28px; }}
  .section-title {{ font-size: 10px; letter-spacing: 3px; color: #4b5563; text-transform: uppercase; margin-bottom: 12px; border-left: 3px solid #00ff88; padding-left: 10px; }}
  .data-table {{ width: 100%; border-collapse: collapse; }}
  .data-table th {{ background: #111827; color: #4b5563; font-size: 9px; letter-spacing: 2px; text-transform: uppercase; padding: 8px 12px; text-align: left; border-bottom: 1px solid #1f2937; }}
  .data-table td {{ border-bottom: 1px solid #111827; font-size: 11px; color: #9ca3af; }}
  .data-table tr:hover td {{ background: #111827; }}
  .meta-item {{ margin-bottom: 6px; font-size: 11px; }}
  .meta-label {{ color: #4b5563; }}
  .intel-item {{ margin-bottom: 8px; font-size: 11px; color: #9ca3af; padding: 6px 10px; background: #111827; border-left: 2px solid #1f2937; }}
  .intel-label {{ color: #6b7280; }}
  .footer {{ border-top: 1px solid #1f2937; padding-top: 16px; margin-top: 28px; font-size: 9px; color: #374151; display: flex; justify-content: space-between; }}
  a {{ color: #60a5fa; text-decoration: none; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="logo">HELIX</div>
    <div class="subtitle">OSINT IDENTITY INVESTIGATION REPORT</div>
  </div>
  <div class="header-right">
    <div>Target: <span style="color:#e5e7eb">@{username}</span></div>
    {email_line}
    <div>Generated: {ts}</div>
    <div>Platforms scanned: {len(results)}</div>
    <div>Scan time: {scan_time:.1f}s</div>
  </div>
</div>

<div class="stats-row">
  <div class="stat-box"><div class="stat-num green">{len(found)}</div><div class="stat-label">Profiles Found</div></div>
  <div class="stat-box"><div class="stat-num blue">{len(high_conf)}</div><div class="stat-label">OG Verified</div></div>
  <div class="stat-box"><div class="stat-num amber">{len(phash_matches or [])}</div><div class="stat-label">Avatar Matches</div></div>
  <div class="stat-box"><div class="stat-num pink">{len(pivot_data or {})}</div><div class="stat-label">Alias Pivots</div></div>
</div>

<div class="section">
  <div class="section-title">✓ Confirmed Profiles ({len(found)})</div>
  <table class="data-table">
    <tr><th>Platform</th><th>Detection</th><th>Identity</th><th>Source</th><th>URL</th></tr>
    {rows}
  </table>
</div>

{wb_section}
{gh_section}
{ph_section}
{crt_section}
{rel_section}
{breach_section}
{dw_section}

<div class="footer">
  <div>Helix v3.3 · github.com/thalha-a9/helix · @thalha-a9</div>
  <div>For authorized security research and OSINT investigations only</div>
</div>

</body>
</html>"""
    return html


def generate_pdf_report(username: str, results: List[Dict],
                         output_dir: str,
                         email: str = "",
                         email_results: List[Dict] = None,
                         wayback_data: Dict = None,
                         github_intel: Dict = None,
                         crt_data: Dict = None,
                         paste_data: Dict = None,
                         phash_matches: List[Dict] = None,
                         pivot_data: Dict = None,
                         breach_verdicts: List[Dict] = None,
                         darkweb: Dict = None,
                         relationships: List[Dict] = None,
                         scan_time: float = 0) -> Dict[str, str]:
    """
    Generate PDF (if weasyprint installed) and HTML investigation report.
    Returns {"html": path, "pdf": path or None}
    """
    html_content = _build_html(
        username=username, results=results, email=email,
        email_results=email_results or [],
        wayback_data=wayback_data or {},
        github_intel=github_intel or {},
        crt_data=crt_data or {},
        paste_data=paste_data or {},
        phash_matches=phash_matches or [],
        pivot_data=pivot_data or {},
        breach_verdicts=breach_verdicts or [],
        darkweb=darkweb or {},
        relationships=relationships or [],
        scan_time=scan_time,
    )

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    label = username.replace(".", "_").replace(" ", "_")
    html_path = os.path.join(output_dir, f"{label}_report_{ts}.html")
    pdf_path  = None

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    if HAS_WEASYPRINT:
        try:
            pdf_path = os.path.join(output_dir, f"{label}_report_{ts}.pdf")
            WP_HTML(string=html_content, base_url=output_dir).write_pdf(pdf_path)
        except Exception as e:
            pdf_path = None

    return {"html": html_path, "pdf": pdf_path}
