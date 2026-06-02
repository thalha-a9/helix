# Helix Changelog

## v3.3.0 — 2026-06-02

### New Features
- **Email permutation engine** (`--email-permute`) — generates likely email addresses from username + extracted real name, optionally checks each with holehe
- **PDF/HTML investigation report** (`--report`) — standalone shareable report with all findings, Wayback data, GitHub intel, avatar matches, CRT domains. PDF output requires `pip install weasyprint`
- **Real name extraction** — automatically extracts display names from OG-verified profiles (e.g. "Mohammad Aqib" from Dribbble) and uses them for email permutation
- **Maigret adapter** (`--maigret`) — loads soxoj/maigret database at runtime, adds 2000+ platforms with sophisticated presenceStrs/absenceStrs detection
- **Sherlock adapter fixed** — updated to new `sherlock_project/resources/data.json` path (v0.16.0 repo restructure)

### False Positive Fixes (7-layer verifier v3.2 → v3.3)
- **Registration API trap** — 41 URL patterns now blocked pre-request in WMN adapter. These return HTTP 200 to mean "username is FREE", not "profile exists" (WordPress.org, Scratch, Quizlet, BoardGameGeek, Duolingo, TryHackMe, BodyBuilding.com, Arch Linux GitLab, visnesscard, TAPiTAG, Známija GraphQL, and more)
- **Dead host pre-filter** — 35 dead/parked hostnames blocked before any HTTP request (taringa.net, lor.sh, hiberworld.com, chatango.com, wego.social, codeproject.com, and more)
- **Login-gate blocked hosts** — 40+ platforms that always redirect to login/CAPTCHA regardless of profile existence (PayPal.me, Tinder, Vivino, Magix, Flightradar24, Bentbox, igromania, 3DNews, etc.)
- **Soft-404 content detection** — 45+ "not found" strings checked in page body before accepting a result
- **Search-page URL blocking** — OP.GG, Scribd search, Carmasters search, and 10+ other search pages that return results for any query
- **Sherlock false positives** — pr0gramm, Anilist, Apple Discussions, archive.org, mercadolivre, hashnode, authorstream, cssbattle, dailymotion, kaskus, Kik, splice, academia.edu added to gate list
- **patriots.win** — "Error: invalid user" served as 200 OK, now blocked
- **graph.py crash** — fixed `int64` not JSON serializable (numpy type from phash distance values)

### Platform Count (with all sources)
| Source | Platforms |
|--------|-----------|
| Builtin | 56 |
| WhatsMyName | ~600 |
| Sherlock | ~360 |
| Maigret | ~2,160 |
| **Total (deduplicated)** | **~3,176** |
| Email (holehe) | 120+ |

---

## v3.2.0 — 2026-05-31

### New Features
- **7-layer heuristic false positive engine** — complete rewrite of verifier.py
  - L1: WAF/CAPTCHA page detection (12 signatures)
  - L2: Registration API trap (17 URL patterns)
  - L3: Soft-404 content scan (30+ strings)
  - L4: Bad redirect path check (20 paths)
  - L5: Dead/parked site detection (8 hosts)
  - L6: Generic title/login page detection
  - L7: Per-platform username format validation (Twitter/X, WordPress, Scratch, BGG, ArtStation, PyPI, npm)
- **WMN adapter v1.2** — pre-flight filter blocks registration APIs and dead hosts before any request
- **Page text passthrough** — checker now stores response body slice for verifier content-based layers
- **Maigret adapter** — initial implementation

### Bug Fixes
- Removed `_page_text` from JSON report output (internal field only)
- Version string consistency across helix.py, pyproject.toml, argparse

---

## v3.1.0 — 2026-05-28

- Initial v3 release with async engine, D3.js graph, WMN/Sherlock adapters
- pHash avatar matching
- Recursive bio pivot
- Wayback Machine module
- GitHub deep recon
- Certificate transparency (crt.sh)
- Paste intelligence (Gist + Pastebin)
- AI verification layer (Claude, OpenRouter, NVIDIA NIM)
