"""
Helix: page capture (`--save-pages`).

For every account Helix reports, keep the exact page it received when the
account was found: the raw response bytes, the response headers, the URL
requested and the URL it ended on, and the UTC time it arrived. Each page is
hashed with SHA-256, and a manifest lists every page with its hash, so anyone
can later show what a profile said at that moment, even if it is edited or
deleted afterwards, and that the saved copy has not been changed since.

Layout, inside the scan's output directory:

  <label>_pages/
    manifest.json        every capture, its metadata and the SHA-256 of its bytes
    index.html           the same, for people: open it in a browser
    001_GitHub.txt       the raw response bytes, unchanged

Pages are written with a .txt extension on purpose: opened in a browser they
show as source text, so a saved page can never run its scripts on the
analyst's machine. The hash covers the exact bytes received.

Set-Cookie and similar headers are dropped: they carry the session the site
handed to Helix, not anything about the account.
"""

import hashlib
import html
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from osint import __version__

SCHEMA = "helix.pages.v1"
MANIFEST = "manifest.json"
DROP_HEADERS = {"set-cookie", "set-cookie2", "cookie", "authorization", "proxy-authorization"}


def utc_now_ms() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def snapshot(status: int, requested_url: str, final_url: str, headers, body: bytes,
             cap: int) -> dict:
    """What check_platform keeps for a hit, taken the moment the page arrived."""
    pairs = headers.items() if hasattr(headers, "items") else headers
    return {
        "fetched_utc": utc_now_ms(),
        "status": status,
        "requested_url": requested_url,
        "final_url": final_url,
        "headers": [[str(k), str(v)] for k, v in pairs if str(k).lower() not in DROP_HEADERS],
        "body": bytes(body[:cap]),
        "truncated": len(body) >= cap,
    }


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")[:60] or "site"


def save(out_dir: str, label: str, username: str, results: List[dict],
         captures: Dict[str, dict]) -> Optional[dict]:
    """
    Write a capture for every result that is still `found`. Adds page_file and
    page_sha256 to those results. Returns the manifest (with `_dir` and
    `_sha256` for the caller), or None when nothing was captured.
    """
    kept = [r for r in results if r.get("found") and r.get("platform") in captures]
    if not kept:
        return None
    pages_dir = os.path.join(out_dir, f"{label}_pages")
    os.makedirs(pages_dir, exist_ok=True)

    entries = []
    for i, r in enumerate(sorted(kept, key=lambda x: str(x["platform"]).lower()), 1):
        cap = captures[r["platform"]]
        body = cap["body"]
        fname = f"{i:03d}_{_safe(str(r['platform']))}.txt"
        with open(os.path.join(pages_dir, fname), "wb") as f:
            f.write(body)
        digest = sha256(body)
        r["page_file"] = f"{label}_pages/{fname}"
        r["page_sha256"] = digest
        entries.append({
            "platform": r["platform"],
            "profile_url": r.get("url"),
            "requested_url": cap["requested_url"],
            "final_url": cap["final_url"],
            "status": cap["status"],
            "fetched_utc": cap["fetched_utc"],
            "headers": cap["headers"],
            "file": fname,
            "bytes": len(body),
            "truncated": cap["truncated"],
            "sha256": digest,
        })

    manifest = {
        "schema": SCHEMA,
        "tool": {"name": "Helix", "version": __version__},
        "username": username,
        "written_utc": utc_now_ms(),
        "note": ("Raw responses exactly as received when each account was found. "
                 "Files are plain text on purpose; the SHA-256 covers the exact bytes."),
        "pages": entries,
    }
    raw = json.dumps(manifest, indent=1, ensure_ascii=False).encode("utf-8")
    with open(os.path.join(pages_dir, MANIFEST), "wb") as f:
        f.write(raw)
    with open(os.path.join(pages_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(_index_html(manifest))
    manifest["_dir"] = pages_dir
    manifest["_sha256"] = sha256(raw)
    return manifest


def verify(pages_dir: str, expected_manifest_sha256: Optional[str] = None) -> List[str]:
    """Problems with a saved-pages directory; [] when every page is intact."""
    path = os.path.join(pages_dir, MANIFEST)
    if not os.path.exists(path):
        return [f"no {MANIFEST} in {pages_dir}"]
    with open(path, "rb") as f:
        raw = f.read()
    problems = []
    if expected_manifest_sha256 and sha256(raw) != expected_manifest_sha256:
        problems.append("manifest does not match the hash recorded in the evidence")
    manifest = json.loads(raw)
    for p in manifest.get("pages", []):
        fp = os.path.join(pages_dir, p["file"])
        if not os.path.exists(fp):
            problems.append(f"missing page {p['file']}")
            continue
        with open(fp, "rb") as f:
            if sha256(f.read()) != p["sha256"]:
                problems.append(f"page changed since capture: {p['file']} ({p['platform']})")
    return problems


def _link(url) -> str:
    u = html.escape(str(url or ""))
    if re.match(r"(?i)^https?://", str(url or "")):
        return f'<a href="{u}" rel="noopener noreferrer">{u}</a>'
    return u


def _index_html(manifest: dict) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(str(p['platform']))}</td>"
        f"<td><a href=\"{html.escape(p['file'])}\">{html.escape(p['file'])}</a></td>"
        f"<td>{p['status']}</td><td>{html.escape(p['fetched_utc'])}</td>"
        f"<td>{_link(p['final_url'])}</td>"
        f"<td class=\"hash\"><code>{p['sha256']}</code></td>"
        f"<td>{p['bytes']:,}{' (cut at cap)' if p['truncated'] else ''}</td></tr>"
        for p in manifest["pages"])
    title = f"Helix saved pages: @{html.escape(str(manifest['username']))}"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{title}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:24px;color:#111;background:#fff}}
 table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ccc;padding:6px;vertical-align:top}}
 th{{background:#f3f3f3;text-align:left}} code{{font-size:12px;word-break:break-all}}
 a{{word-break:break-all}} .scroll{{overflow-x:auto}}
 td.hash code{{display:inline-block;min-width:32ch}}
 @media (prefers-color-scheme:dark){{body{{color:#eee;background:#111}} th{{background:#222}} td,th{{border-color:#444}} a{{color:#8ab4f8}}}}
</style></head><body>
<h1>{title}</h1>
<p>Helix {html.escape(str(manifest['tool']['version']))} | written {html.escape(manifest['written_utc'])} |
{len(manifest['pages'])} page(s). Each file is the raw response exactly as received when the
account was found, saved as text so it cannot run scripts. Check them all with
<code>helix-osint --verify-pages &lt;this folder&gt;</code>.</p>
<div class="scroll"><table><tr><th>Platform</th><th>Saved page</th><th>HTTP</th><th>Fetched (UTC)</th>
<th>Final URL</th><th>SHA-256 of the bytes</th><th>Bytes</th></tr>{rows}</table></div>
</body></html>
"""
