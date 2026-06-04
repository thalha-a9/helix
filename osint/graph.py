"""Helix v3.0 — D3.js Network Graph Generator"""
import json
import html as _html
from datetime import datetime
from osint.platforms import CATEGORY_META


def _build_cross_links(found, node_id_by_platform, username):
    cross_links = []
    for r in found:
        bio_links = r.get("bio_links", {})
        src_id = node_id_by_platform.get(r["platform"])
        if src_id is None: continue
        for bio_key, bio_handle in bio_links.items():
            if bio_handle.lower() not in (username.lower(), username.lower().replace("_","")):
                continue
            target_plat = next((r2["platform"] for r2 in found
                if bio_key.lower() in r2["platform"].lower()), None)
            if target_plat:
                tgt_id = node_id_by_platform.get(target_plat)
                if tgt_id is not None and src_id != tgt_id:
                    pair = tuple(sorted([src_id, tgt_id]))
                    if not any(tuple(sorted([c["source"],c["target"]]))==pair for c in cross_links):
                        cross_links.append({"source":src_id,"target":tgt_id,"type":"cross_link","via":bio_key})
    return cross_links


def generate_graph(username, results, output_path,
                   email=None, email_results=None,
                   pivot_data=None, phash_matches=None):

    found        = [r for r in results if r.get("found")]
    not_found    = [r for r in results if not r.get("found") and not r.get("error")]
    errors       = [r for r in results if r.get("error")]
    email_found  = [r for r in (email_results or []) if r.get("found")]

    nodes=[]; links=[]; node_id_by_platform={}
    nid=0

    # Root: username
    nodes.append({"id":0,"label":f"@{username}","type":"target","category":"target",
                  "color":"#ffffff","url":"","size":30,"root_type":"username"})
    nid=1

    # Root: email
    email_root_id=None
    if email:
        nodes.append({"id":nid,"label":email,"type":"target","category":"target",
                      "color":"#fbbf24","url":"","size":22,"root_type":"email"})
        email_root_id=nid; nid+=1

    # Category nodes
    cats_found = list({r["category"] for r in found})
    cats_email = list({r["category"] for r in email_found})
    all_cats   = list(set(cats_found+cats_email))
    cat_ids    = {}
    for cat in all_cats:
        meta = CATEGORY_META.get(cat,{"label":cat,"node_color":"#94a3b8"})
        nodes.append({"id":nid,"label":meta["label"],"type":"category","category":cat,
                      "color":meta["node_color"],"url":"","size":18})
        if cat in cats_found:
            links.append({"source":0,"target":nid,"type":"category"})
        if email_root_id and cat in cats_email:
            links.append({"source":email_root_id,"target":nid,"type":"category"})
        cat_ids[cat]=nid; nid+=1

    # Platform nodes
    for r in found:
        nodes.append({"id":nid,"label":r["platform"],"type":"platform",
                      "category":r["category"],"color":r["color"],"url":r["url"],
                      "size":12,"confidence":r.get("confidence","low"),
                      "source":r.get("source","builtin"),"og_title":r.get("og_title",""),
                      "phash":bool(r.get("phash",""))})
        node_id_by_platform[r["platform"]]=nid
        links.append({"source":cat_ids.get(r["category"],0),"target":nid,"type":"platform"})
        nid+=1

    for r in email_found:
        if r["platform"] in node_id_by_platform:
            if email_root_id:
                links.append({"source":email_root_id,"target":node_id_by_platform[r["platform"]],"type":"email_also"})
        else:
            nodes.append({"id":nid,"label":r["platform"],"type":"platform",
                          "category":r["category"],"color":r["color"],"url":r["url"],
                          "size":12,"confidence":"high","source":"email","og_title":"","phash":False})
            node_id_by_platform[r["platform"]]=nid
            links.append({"source":cat_ids.get(r["category"],email_root_id or 0),"target":nid,"type":"platform"})
            nid+=1

    # Pivot nodes
    pivot_root_ids={}
    for alias, pd in (pivot_data or {}).items():
        p_root_id=nid
        nodes.append({"id":nid,"label":f"@{alias}","type":"pivot_root","category":"pivot",
                      "color":"#f59e0b","url":"","size":20,
                      "depth":pd["depth"],"discovered_via":pd["discovered_via"]})
        links.append({"source":0,"target":nid,"type":"pivot"})
        pivot_root_ids[alias]=nid; nid+=1
        for r in pd.get("found",[]):
            nodes.append({"id":nid,"label":r["platform"],"type":"platform",
                          "category":r["category"],"color":r["color"],"url":r["url"],
                          "size":10,"confidence":r.get("confidence","low"),
                          "source":"pivot","og_title":"","phash":False})
            links.append({"source":p_root_id,"target":nid,"type":"pivot_platform"})
            nid+=1

    cross_links = _build_cross_links(found, node_id_by_platform, username)
    links.extend(cross_links)

    # pHash match links
    for m in (phash_matches or []):
        s=node_id_by_platform.get(m["platform_a"])
        t=node_id_by_platform.get(m["platform_b"])
        if s and t:
            links.append({"source":s,"target":t,"type":"phash_match",
                          "confidence":m["confidence"],"distance":m["distance"]})

    ghost_nodes=[{"platform":r["platform"],"url":r["url"],"category":r["category"]}
                 for r in not_found]

    ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total=len(results); found_cnt=len(found); error_cnt=len(errors)
    xlink_cnt=len(cross_links); pivot_cnt=len(pivot_data or {})
    phash_cnt=len(phash_matches or [])

    high_conf  = sum(1 for r in found if r.get("confidence")=="high")
    med_conf   = sum(1 for r in found if r.get("confidence")=="medium")
    low_conf   = sum(1 for r in found if r.get("confidence")=="low")

    cat_breakdown = {}
    for r in found:
        cat=r.get("category","other")
        cat_breakdown[cat]=cat_breakdown.get(cat,0)+1
    src_breakdown = {}
    for r in found:
        src=r.get("source","builtin")
        src_breakdown[src]=src_breakdown.get(src,0)+1

    cat_bars=""
    for cat, cnt in sorted(cat_breakdown.items(), key=lambda x:-x[1]):
        meta=CATEGORY_META.get(cat,{"label":cat,"node_color":"#94a3b8"})
        pct=int((cnt/max(found_cnt,1))*100)
        cat_bars+=f'<div class="bar-row"><span class="bar-label">{meta["label"]}</span><div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{meta["node_color"]}"></div></div><span class="bar-count">{cnt}</span></div>\n'

    src_rows=""
    for src, cnt in sorted(src_breakdown.items(), key=lambda x:-x[1]):
        src_rows+=f'<div class="src-row"><span class="src-badge">{src}</span><span class="src-cnt">{cnt}</span></div>\n'

    nodes_json=json.dumps(nodes, default=lambda o: int(o) if hasattr(o,'item') else str(o))
    links_json=json.dumps(links, default=lambda o: int(o) if hasattr(o,'item') else str(o))
    ghosts_json=json.dumps(ghost_nodes, default=lambda o: int(o) if hasattr(o,'item') else str(o))

    html=f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Helix — {username}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js" integrity="sha512-MefNfAGJ/pEy89xLOFs3V6pYPs6AmUhXOXCBDc3V7xSdX2jSCp2l0vEdBkCXSHtdMPFCMZs+8ElEMkTFVoNw==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<style>
:root{{--bg:#050508;--panel:#0a0a0f;--panel2:#0f0f18;--border:#1a1a2e;
  --accent:#00ff88;--accent2:#f59e0b;--accent3:#a78bfa;--accent4:#f472b6;
  --text:#c8d3e0;--dim:#3a4458;--red:#ef4444;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;overflow:hidden;height:100vh;display:flex;flex-direction:column;}}

/* ── Top bar ── */
#topbar{{
  background:rgba(5,5,8,0.98);border-bottom:1px solid var(--border);
  padding:0 16px;height:44px;display:flex;align-items:center;justify-content:space-between;
  flex-shrink:0;z-index:100;
}}
.tb-left{{display:flex;align-items:center;gap:16px;}}
.tb-logo{{color:var(--accent);font-size:13px;font-weight:bold;letter-spacing:3px;}}
.tb-target{{color:var(--text);font-size:12px;opacity:.7;}}
.tb-pills{{display:flex;gap:8px;}}
.pill{{background:var(--panel2);border:1px solid var(--border);border-radius:20px;
  padding:2px 10px;font-size:10px;color:var(--dim);}}
.pill.green{{border-color:#00ff8844;color:var(--accent);}}
.pill.amber{{border-color:#f59e0b44;color:var(--accent2);}}
.pill.purple{{border-color:#a78bfa44;color:var(--accent3);}}
.pill.pink{{border-color:#f472b644;color:var(--accent4);}}
.tb-right{{display:flex;gap:8px;}}
.tb-btn{{background:transparent;border:1px solid var(--border);border-radius:3px;
  color:var(--dim);cursor:pointer;font-family:'Courier New',monospace;font-size:10px;
  padding:4px 10px;transition:all .15s;}}
.tb-btn:hover,.tb-btn.active{{border-color:var(--accent);color:var(--accent);}}
.tb-btn.red:hover{{border-color:var(--red);color:var(--red);}}

/* ── Layout ── */
#main{{display:flex;flex:1;overflow:hidden;}}

/* ── Side panel ── */
#sidepanel{{
  width:240px;background:var(--panel);border-right:1px solid var(--border);
  overflow-y:auto;flex-shrink:0;display:flex;flex-direction:column;
  transition:width .2s;
}}
#sidepanel.collapsed{{width:0;overflow:hidden;}}
#sidepanel::-webkit-scrollbar{{width:3px;}}
#sidepanel::-webkit-scrollbar-thumb{{background:var(--border);}}

.sp-section{{border-bottom:1px solid var(--border);padding:14px 14px 12px;}}
.sp-title{{font-size:9px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;margin-bottom:10px;}}
.stat-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;}}
.stat-box{{background:var(--panel2);border:1px solid var(--border);border-radius:4px;
  padding:8px;text-align:center;}}
.stat-box .sv{{font-size:20px;font-weight:bold;line-height:1;}}
.stat-box .sl{{font-size:9px;color:var(--dim);margin-top:3px;}}
.stat-box.green .sv{{color:var(--accent);}}
.stat-box.amber .sv{{color:var(--accent2);}}
.stat-box.purple .sv{{color:var(--accent3);}}
.stat-box.red .sv{{color:var(--red);}}

.conf-row{{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;font-size:11px;}}
.conf-dot{{width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-right:8px;}}
.conf-row-inner{{display:flex;align-items:center;}}

.bar-row{{display:flex;align-items:center;gap:6px;margin-bottom:7px;font-size:10px;}}
.bar-label{{width:64px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:9px;}}
.bar-track{{flex:1;height:4px;background:var(--panel2);border-radius:2px;overflow:hidden;}}
.bar-fill{{height:100%;border-radius:2px;transition:width .5s;}}
.bar-count{{color:var(--accent);font-size:9px;min-width:18px;text-align:right;}}

.src-row{{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;}}
.src-badge{{font-size:9px;background:var(--panel2);border:1px solid var(--border);border-radius:3px;padding:1px 6px;color:var(--dim);}}
.src-cnt{{font-size:11px;color:var(--accent);}}

/* ── Filter panel ── */
#filterpanel{{
  position:absolute;top:56px;left:248px;z-index:90;
  background:var(--panel);border:1px solid var(--border);border-radius:4px;
  padding:12px;min-width:180px;display:none;
  box-shadow:0 8px 32px rgba(0,0,0,.6);
}}
#filterpanel.visible{{display:block;}}
.fp-title{{font-size:9px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;margin-bottom:10px;}}
.fp-row{{display:flex;align-items:center;gap:8px;margin-bottom:7px;font-size:11px;cursor:pointer;}}
.fp-row input{{accent-color:var(--accent);}}

/* ── Graph canvas ── */
#graph-wrap{{flex:1;position:relative;overflow:hidden;}}
svg#graph{{width:100%;height:100%;}}

/* ── Links ── */
.link{{stroke-opacity:.3;}}
.link.category{{stroke:#1a1a2e;stroke-width:2px;stroke-dasharray:6,4;}}
.link.platform{{stroke:#1e2435;stroke-width:1px;}}
.link.email_also{{stroke:#f59e0b;stroke-width:1.5px;stroke-dasharray:4,3;stroke-opacity:.5;}}
.link.pivot{{stroke:#f59e0b;stroke-width:2px;stroke-dasharray:6,3;stroke-opacity:.6;}}
.link.pivot_platform{{stroke:#f59e0b44;stroke-width:1px;}}
.link.cross_link{{stroke:var(--accent);stroke-width:2.5px;stroke-opacity:.9;
  animation:lp 3s ease-in-out infinite;}}
.link.phash_match{{stroke:var(--accent4);stroke-width:2px;stroke-dasharray:4,2;stroke-opacity:.8;
  animation:lp 2s ease-in-out infinite;}}
@keyframes lp{{0%,100%{{stroke-opacity:.9;}}50%{{stroke-opacity:.3;}}}}

/* ── Nodes ── */
.node circle{{stroke-width:1.5px;cursor:pointer;}}
.node text{{font-family:'Courier New',monospace;font-size:9px;fill:#8899aa;pointer-events:none;text-anchor:middle;}}
.conf-ring{{fill:none;stroke-width:1.5px;stroke-dasharray:3,2;pointer-events:none;opacity:.6;}}

@keyframes pulse-white{{0%,100%{{filter:drop-shadow(0 0 6px #fff);}}50%{{filter:drop-shadow(0 0 18px var(--accent));}}}}
@keyframes pulse-amber{{0%,100%{{filter:drop-shadow(0 0 6px var(--accent2));}}50%{{filter:drop-shadow(0 0 18px var(--accent2));}}}}
@keyframes pulse-pivot{{0%,100%{{filter:drop-shadow(0 0 5px var(--accent2));}}50%{{filter:drop-shadow(0 0 14px var(--accent2));}}}}
.node-target circle{{animation:pulse-white 2.5s infinite;}}
.node-email-target circle{{animation:pulse-amber 2.5s infinite;}}
.node-pivot-root circle{{animation:pulse-pivot 2.5s infinite;}}

/* ── Tooltip ── */
#tooltip{{
  position:fixed;background:var(--panel);border:1px solid var(--accent);
  border-radius:4px;padding:10px 14px;font-size:11px;pointer-events:none;
  opacity:0;transition:opacity .15s;max-width:280px;z-index:200;
  box-shadow:0 0 30px rgba(0,255,136,.1);
}}
.tt-name{{color:var(--accent);font-weight:bold;margin-bottom:6px;font-size:12px;}}
.tt-meta{{color:var(--dim);font-size:10px;margin-bottom:3px;}}
.tt-conf-high{{color:var(--accent);font-size:10px;}}
.tt-conf-med{{color:#60a5fa;font-size:10px;}}
.tt-conf-low{{color:var(--dim);font-size:10px;}}
.tt-og{{color:var(--accent3);font-size:10px;margin-top:4px;font-style:italic;}}
.tt-xlink{{color:var(--accent);font-size:10px;margin-top:4px;}}
.tt-phash{{color:var(--accent4);font-size:10px;margin-top:4px;}}
.tt-url{{color:var(--dim);font-size:9px;margin-top:5px;word-break:break-all;}}
.tt-open{{color:#60a5fa;font-size:9px;margin-top:4px;}}

/* ── Search ── */
#searchbar{{
  position:absolute;top:10px;left:50%;transform:translateX(-50%);
  background:var(--panel);border:1px solid var(--border);border-radius:4px;
  padding:6px 14px;display:none;align-items:center;gap:8px;z-index:100;
  box-shadow:0 4px 20px rgba(0,0,0,.5);
}}
#searchbar.visible{{display:flex;}}
#searchinput{{background:transparent;border:none;outline:none;color:var(--text);
  font-family:'Courier New',monospace;font-size:12px;width:200px;}}
#searchinput::placeholder{{color:var(--dim);}}

/* ── Ghost overlay ── */
#ghost-label{{
  position:absolute;bottom:16px;left:50%;transform:translateX(-50%);
  font-size:9px;color:var(--dim);letter-spacing:1px;pointer-events:none;display:none;
}}

/* ── Legend ── */
#legend{{
  position:absolute;bottom:16px;right:16px;background:rgba(5,5,8,.92);
  border:1px solid var(--border);border-radius:4px;padding:10px 14px;font-size:10px;z-index:50;
}}
.leg-row{{display:flex;align-items:center;gap:8px;margin-bottom:5px;color:var(--dim);}}
.leg-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0;}}
.leg-line{{width:20px;height:2px;border-radius:1px;flex-shrink:0;}}
.leg-dash{{width:20px;height:2px;border-radius:1px;flex-shrink:0;
  background:repeating-linear-gradient(90deg,currentColor 0,currentColor 4px,transparent 4px,transparent 7px);}}
</style>
</head>
<body>

<div id="topbar">
  <div class="tb-left">
    <span class="tb-logo">HELIX</span>
    <span class="tb-target">{username}{(' · ' + email) if email else ''}</span>
    <div class="tb-pills">
      <span class="pill green">{found_cnt} found</span>
      {'<span class="pill amber">' + str(pivot_cnt) + ' pivots</span>' if pivot_cnt else ''}
      {'<span class="pill purple">' + str(xlink_cnt) + ' cross-links</span>' if xlink_cnt else ''}
      {'<span class="pill pink">' + str(phash_cnt) + ' avatar matches</span>' if phash_cnt else ''}
    </div>
  </div>
  <div class="tb-right">
    <button class="tb-btn" onclick="togglePanel()" id="btn-panel">◧ Panel</button>
    <button class="tb-btn" onclick="toggleFilter()" id="btn-filter">⊞ Filter</button>
    <button class="tb-btn" onclick="toggleSearch()" id="btn-search">⌕ Search</button>
    <button class="tb-btn" onclick="toggleGhosts()" id="btn-ghost">◌ Not found</button>
    <button class="tb-btn" onclick="toggleLabels()" id="btn-labels">☰ Labels</button>
    <button class="tb-btn" onclick="exportSVG()">↓ Export</button>
    <button class="tb-btn" onclick="resetZoom()">⟳ Reset</button>
  </div>
</div>

<div id="main">
  <div id="sidepanel">
    <div class="sp-section">
      <div class="sp-title">Scan Summary</div>
      <div class="stat-grid">
        <div class="stat-box green"><div class="sv">{found_cnt}</div><div class="sl">Found</div></div>
        <div class="stat-box"><div class="sv" style="color:var(--text)">{total}</div><div class="sl">Checked</div></div>
        <div class="stat-box amber"><div class="sv">{xlink_cnt}</div><div class="sl">Cross-links</div></div>
        <div class="stat-box red"><div class="sv">{error_cnt}</div><div class="sl">Errors</div></div>
      </div>
    </div>

    <div class="sp-section">
      <div class="sp-title">Confidence</div>
      <div class="conf-row"><div class="conf-row-inner"><div class="conf-dot" style="background:var(--accent)"></div>High (OG verified)</div><span style="color:var(--accent)">{high_conf}</span></div>
      <div class="conf-row"><div class="conf-row-inner"><div class="conf-dot" style="background:#60a5fa"></div>Medium</div><span style="color:#60a5fa">{med_conf}</span></div>
      <div class="conf-row"><div class="conf-row-inner"><div class="conf-dot" style="background:var(--dim)"></div>Low</div><span style="color:var(--dim)">{low_conf}</span></div>
    </div>

    <div class="sp-section">
      <div class="sp-title">By Category</div>
      {cat_bars}
    </div>

    <div class="sp-section">
      <div class="sp-title">By Source</div>
      {src_rows}
    </div>

    <div class="sp-section">
      <div class="sp-title">Scan Info</div>
      <div style="font-size:9px;color:var(--dim);line-height:1.7">
        <div>Target: <span style="color:var(--text)">@{username}</span></div>
        {'<div>Email: <span style="color:var(--accent2)">'+email+'</span></div>' if email else ''}
        <div>Time: <span style="color:var(--text)">{ts}</span></div>
        <div>Pivots: <span style="color:var(--accent2)">{pivot_cnt}</span></div>
        <div>pHash: <span style="color:var(--accent4)">{phash_cnt} match(es)</span></div>
      </div>
    </div>
  </div>

  <div id="graph-wrap">
    <svg id="graph"></svg>

    <div id="filterpanel">
      <div class="fp-title">Filter by Confidence</div>
      <label class="fp-row"><input type="checkbox" id="f-high" checked onchange="applyFilter()"> High (OG verified)</label>
      <label class="fp-row"><input type="checkbox" id="f-med" checked onchange="applyFilter()"> Medium</label>
      <label class="fp-row"><input type="checkbox" id="f-low" checked onchange="applyFilter()"> Low</label>
    </div>

    <div id="searchbar">
      <span style="color:var(--dim);font-size:11px">⌕</span>
      <input id="searchinput" placeholder="filter platforms..." autocomplete="off">
    </div>

    <div id="ghost-label">◌ NOT FOUND PLATFORMS</div>

    <div id="legend">
      <div class="leg-row"><div class="leg-line" style="background:var(--accent)"></div>Bio cross-link</div>
      <div class="leg-row"><div class="leg-line" style="background:var(--accent4)"></div>Avatar match</div>
      <div class="leg-row"><div class="leg-dash" style="color:var(--accent2)"></div>Pivot / Email</div>
      <div class="leg-row"><div class="leg-dot" style="background:#ffffff;box-shadow:0 0 6px #fff"></div>Username root</div>
      {'<div class="leg-row"><div class="leg-dot" style="background:var(--accent2);box-shadow:0 0 6px var(--accent2)"></div>Email root</div>' if email else ''}
      <div class="leg-row"><div class="leg-dot" style="border:1.5px solid var(--accent);background:transparent"></div>High confidence</div>
    </div>
  </div>
</div>

<div id="tooltip">
  <div class="tt-name" id="tt-name"></div>
  <div id="tt-conf"></div>
  <div id="tt-src" class="tt-meta"></div>
  <div id="tt-og" class="tt-og"></div>
  <div id="tt-xlink" class="tt-xlink" style="display:none"></div>
  <div id="tt-phash" class="tt-phash" style="display:none"></div>
  <div id="tt-url" class="tt-url"></div>
  <div id="tt-open" class="tt-open"></div>
</div>

<script>
const NODES={nodes_json};
const LINKS={links_json};
const GHOSTS={ghosts_json};

const wrap=document.getElementById("graph-wrap");
const W=()=>wrap.clientWidth, H=()=>wrap.clientHeight;
const svg=d3.select("#graph").attr("width",W()).attr("height",H());
const zoomG=svg.append("g");
const zoom=d3.zoom().scaleExtent([.1,8]).on("zoom",e=>zoomG.attr("transform",e.transform));
svg.call(zoom);

const sim=d3.forceSimulation(NODES)
  .force("link",d3.forceLink(LINKS).id(d=>d.id)
    .distance(d=>{{
      if(d.type==="category") return 200;
      if(d.type==="cross_link"||d.type==="phash_match") return 120;
      if(d.type==="pivot") return 180;
      return 80;
    }}).strength(d=>d.type==="cross_link"||d.type==="phash_match"?.7:.8))
  .force("charge",d3.forceManyBody().strength(-350))
  .force("center",d3.forceCenter(W()/2,H()/2))
  .force("collide",d3.forceCollide().radius(d=>d.size+12));

const link=zoomG.append("g").selectAll("line")
  .data(LINKS).join("line")
  .attr("class",d=>"link "+d.type);

const node=zoomG.append("g").selectAll(".node")
  .data(NODES).join("g")
  .attr("class",d=>{{
    let c="node";
    if(d.type==="target"&&d.root_type==="username") c+=" node-target";
    if(d.type==="target"&&d.root_type==="email") c+=" node-email-target";
    if(d.type==="pivot_root") c+=" node-pivot-root";
    return c;
  }})
  .call(d3.drag()
    .on("start",(e,d)=>{{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}})
    .on("drag",(e,d)=>{{d.fx=e.x;d.fy=e.y;}})
    .on("end",(e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}));

node.append("circle")
  .attr("r",d=>d.size)
  .attr("fill",d=>d.color+(d.type==="platform"?"18":"12"))
  .attr("stroke",d=>d.color);

node.filter(d=>d.confidence==="high"||d.confidence==="medium")
  .append("circle").attr("class","conf-ring")
  .attr("r",d=>d.size+5)
  .attr("stroke",d=>d.confidence==="high"?"#00ff88":"#60a5fa");

node.filter(d=>d.phash)
  .append("circle").attr("class","conf-ring")
  .attr("r",d=>d.size+10)
  .attr("stroke","#f472b6").attr("stroke-opacity",.5).attr("stroke-dasharray","2,3");

node.append("text").attr("dy",d=>d.size+13).text(d=>d.label);

// Tooltip
const tt=document.getElementById("tooltip");
const nodeById=Object.fromEntries(NODES.map(n=>[n.id,n]));
const xMap={{}};
LINKS.filter(l=>l.type==="cross_link").forEach(l=>{{
  const s=typeof l.source==="object"?l.source.id:l.source;
  const t=typeof l.target==="object"?l.target.id:l.target;
  (xMap[s]=xMap[s]||[]).push(t);(xMap[t]=xMap[t]||[]).push(s);
}});
const phMap={{}};
LINKS.filter(l=>l.type==="phash_match").forEach(l=>{{
  const s=typeof l.source==="object"?l.source.id:l.source;
  const t=typeof l.target==="object"?l.target.id:l.target;
  (phMap[s]=phMap[s]||[]).push({{id:t,conf:l.confidence}});
  (phMap[t]=phMap[t]||[]).push({{id:s,conf:l.confidence}});
}});

node.on("mouseover",(e,d)=>{{
  if(d.type==="target"||d.type==="category") return;
  document.getElementById("tt-name").textContent=d.label;
  const confEl=document.getElementById("tt-conf");
  confEl.textContent=d.confidence?`confidence: ${{d.confidence}}`:'';
  confEl.className=d.confidence==="high"?"tt-conf-high":d.confidence==="medium"?"tt-conf-med":"tt-conf-low";
  document.getElementById("tt-src").textContent=d.source?`source: ${{d.source}}`:'';
  document.getElementById("tt-og").textContent=d.og_title?`"${{d.og_title}}"`:'' ;
  const xl=document.getElementById("tt-xlink");
  const partners=(xMap[d.id]||[]).map(id=>nodeById[id]?.label).filter(Boolean);
  xl.textContent=partners.length?`↔ bio-linked: ${{partners.join(", ")}}`:'' ;
  xl.style.display=partners.length?"":"none";
  const ph=document.getElementById("tt-phash");
  const phPartners=(phMap[d.id]||[]);
  ph.textContent=phPartners.length?`≅ avatar match: ${{phPartners.map(p=>nodeById[p.id]?.label+"("+p.conf+")").join(", ")}}`:'' ;
  ph.style.display=phPartners.length?"":"none";
  document.getElementById("tt-url").textContent=d.url;
  document.getElementById("tt-open").textContent=d.url?"click to open →":"";
  tt.style.opacity="1";
}})
.on("mousemove",e=>{{tt.style.left=(e.clientX+16)+"px";tt.style.top=(e.clientY-10)+"px";}})
.on("mouseout",()=>tt.style.opacity="0")
.on("click",(e,d)=>{{if(d.url)window.open(d.url,"_blank");}});

sim.on("tick",()=>{{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
}});

// Panel
let panelOpen=true;
function togglePanel(){{
  panelOpen=!panelOpen;
  document.getElementById("sidepanel").classList.toggle("collapsed",!panelOpen);
  document.getElementById("btn-panel").classList.toggle("active",panelOpen);
  setTimeout(()=>{{sim.force("center",d3.forceCenter(W()/2,H()/2)).alpha(.3).restart();}},220);
}}

// Filter
let filterOpen=false;
function toggleFilter(){{
  filterOpen=!filterOpen;
  document.getElementById("filterpanel").classList.toggle("visible",filterOpen);
  document.getElementById("btn-filter").classList.toggle("active",filterOpen);
}}
function applyFilter(){{
  const showH=document.getElementById("f-high").checked;
  const showM=document.getElementById("f-med").checked;
  const showL=document.getElementById("f-low").checked;
  node.style("opacity",d=>{{
    if(d.type!=="platform") return 1;
    if(d.confidence==="high"&&!showH) return .07;
    if(d.confidence==="medium"&&!showM) return .07;
    if(d.confidence==="low"&&!showL) return .07;
    return 1;
  }});
}}

// Search
let searchOpen=false;
function toggleSearch(){{
  searchOpen=!searchOpen;
  document.getElementById("searchbar").classList.toggle("visible",searchOpen);
  document.getElementById("btn-search").classList.toggle("active",searchOpen);
  if(searchOpen){{document.getElementById("searchinput").focus();document.getElementById("searchinput").value="";doSearch("");}}
  else doSearch("");
}}
function doSearch(q){{
  const lq=q.toLowerCase().trim();
  node.style("opacity",d=>!lq?1:d.label.toLowerCase().includes(lq)?1:.05);
  link.style("opacity",d=>(!lq?null:.04));
}}
document.getElementById("searchinput").addEventListener("input",e=>doSearch(e.target.value));
document.addEventListener("keydown",e=>{{if(e.key==="Escape"){{if(searchOpen)toggleSearch();if(filterOpen)toggleFilter();}}}}); 

// Ghosts
let ghostsOn=false,ghostG=null;
function toggleGhosts(){{
  ghostsOn=!ghostsOn;
  document.getElementById("btn-ghost").classList.toggle("active",ghostsOn);
  document.getElementById("ghost-label").style.display=ghostsOn?"block":"none";
  if(ghostsOn&&!ghostG){{
    ghostG=zoomG.append("g").attr("opacity",.12);
    ghostG.selectAll("circle").data(GHOSTS).join("circle")
      .attr("r",5).attr("fill","none").attr("stroke","#3a4458")
      .attr("cx",(d,i)=>80+(i%25)*44).attr("cy",(d,i)=>H()-90-Math.floor(i/25)*36);
    ghostG.selectAll("text").data(GHOSTS).join("text")
      .attr("fill","#2a3448").attr("font-size","7px").attr("text-anchor","middle")
      .attr("x",(d,i)=>80+(i%25)*44).attr("y",(d,i)=>H()-78-Math.floor(i/25)*36)
      .text(d=>d.platform);
  }}else if(ghostG) ghostG.attr("opacity",ghostsOn?.12:0);
}}

// Labels
let labelsOn=true;
function toggleLabels(){{
  labelsOn=!labelsOn;
  node.selectAll("text").style("display",labelsOn?null:"none");
  document.getElementById("btn-labels").classList.toggle("active",!labelsOn);
}}

// Export SVG
function exportSVG(){{
  const s=document.getElementById("graph").outerHTML;
  const blob=new Blob([s],{{type:"image/svg+xml"}});
  const a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download="helix_{username}.svg";
  a.click();
}}

function resetZoom(){{svg.transition().duration(500).call(zoom.transform,d3.zoomIdentity);}}

window.addEventListener("resize",()=>{{
  svg.attr("width",W()).attr("height",H());
  sim.force("center",d3.forceCenter(W()/2,H()/2)).restart();
}});
</script>
</body>
</html>"""

    with open(output_path,"w",encoding="utf-8") as f:
        f.write(html)
    return output_path
