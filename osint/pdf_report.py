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


def _source_badge(src: str) -> str:
    colors = {"builtin": "#a78bfa", "wmn": "#38bdf8", "sherlock": "#fb923c", "maigret": "#f472b6"}
    c = colors.get(src, "#6b7280")
    return f'<span style="background:{c}22;color:{c};border:1px solid {c}44;border-radius:3px;padding:1px 6px;font-size:10px">{src}</span>'


def _build_html(username: str, results: List[Dict],
                email: str = "", email_results: List[Dict] = None,
                wayback_data: Dict = None, github_intel: Dict = None,
                crt_data: Dict = None, paste_data: Dict = None,
                phash_matches: List[Dict] = None,
                pivot_data: Dict = None,
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
        rows += f'<tr><td colspan="4" style="background:#111827;color:#6b7280;font-size:10px;padding:6px 12px;letter-spacing:2px;text-transform:uppercase">{cat}</td></tr>\n'
        for r in items:
            og = f'<br><span style="color:#a78bfa;font-size:10px;font-style:italic">{r.get("og_title","")[:60]}</span>' if r.get("og_title") else ""
            rows += f"""<tr>
<td style="padding:8px 12px;font-weight:500;color:#e5e7eb">{r['platform']}</td>
<td style="padding:8px 12px">{_confidence_badge(r.get('confidence','low'))}</td>
<td style="padding:8px 12px">{_source_badge(r.get('source','builtin'))}</td>
<td style="padding:8px 12px;font-size:10px;color:#60a5fa;word-break:break-all"><a href="{r['url']}" style="color:#60a5fa">{r['url']}</a>{og}</td>
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
            gh_items += f'<div class="intel-item"><span class="intel-label">Extracted emails:</span> {", ".join(github_intel["emails"])}</div>'
        if github_intel.get("orgs"):
            gh_items += f'<div class="intel-item"><span class="intel-label">Organizations:</span> {", ".join(o["name"] for o in github_intel["orgs"])}</div>'
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
        crt_section = f'<div class="section"><div class="section-title">🔐 Certificate Transparency ({len(domains)} domains)</div><div style="font-family:monospace;font-size:11px;color:#60a5fa;line-height:1.8">{"<br>".join(domains)}</div></div>'

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
    <tr><th>Platform</th><th>Confidence</th><th>Source</th><th>URL</th></tr>
    {rows}
  </table>
</div>

{wb_section}
{gh_section}
{ph_section}
{crt_section}

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
