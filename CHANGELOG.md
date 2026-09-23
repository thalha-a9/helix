# Helix Changelog

## Unreleased

### Operational Security
- **#12** `--proxy` (http/https/socks4/socks5) and `--tor` route every probe — checker, email checker, modules and all adapters. `HTTP(S)_PROXY` honoured as a fallback. The CLI prints its egress and warns when traffic goes out direct. Proxy credentials are redacted from all output.

### Accuracy
- **#24** Identity confidence (HIGH / MEDIUM / LOW) on every finding, computed from independent selectors — avatar match, bio cross-link, email confirmation, real name, location — with the supporting evidence listed. A username match alone is never above LOW; a single selector is never HIGH. Shown in the console and in JSON, CSV, TXT and HTML reports.
- **#17** `--location` flags candidates whose profile states a conflicting location, loudly, before confirmation. Conflicts are downgraded, never purged.
- **#18** `--maigret-engine` runs the installed Maigret engine as a lead source. Every hit is re-fetched and verified by Helix before it can reach a report; platforms Helix already checks keep Helix's own definition.
- New verifier layer: a homepage-only "hit" (a site root that never mentions the username, e.g. Maigret reporting Discord's homepage) is always purged, for every source.
- **GitLab false positive fixed** — groups share the user URL space (`gitlab.com/torvalds` is a group), so a group was reported as the user's account. GitLab is now checked through the users API, which only returns real users.
- **Bio link false positives fixed** — the Open Graph namespace (`http://ogp.me/ns#`) and asset CDNs in page source were reported as the user's website and counted as cross-links.

### Testing
- **#9** Test suite (870 tests) and CI on Python 3.9 / 3.11 / 3.12, including a false-positive harness that feeds a "user does not exist" response for every platform through detection and the verifier.

---

## v3.4.0 — 2026-06-05

### Security Fixes (14 issues resolved)
- **#1** SSL/TLS verification now enabled by default (`ssl=True`) — was globally disabled
- **#2** `--output` path sanitized with `os.path.realpath()` — prevents directory traversal
- **#3** Sherlock integrity validation — response must be dict with 10+ keys before use
- **#4** Gravatar email hash changed from MD5 to SHA256
- **#5** Dependencies pinned with version ranges in requirements.txt
- **#7** `KeyboardInterrupt` no longer swallowed by bare `except` blocks
- **#8** `_check_deps()` moved to `main()` — no longer calls `sys.exit()` at import time
- **#10** XSS fixed in HTML report and graph — all user-controlled data HTML-escaped
- **#11** D3.js loaded with SRI integrity hash and `crossorigin="anonymous"`
- **#13** `install.sh` stale repo name `osint-grapher` replaced with `helix`
- **#14** HTTP response body capped at 512KB — prevents memory exhaustion

### False Positive Fixes
- **Default avatar filtering** — pHash no longer reports matches when 3+ platforms share the same hash (Mastodon grey silhouette, CDN placeholders)
- **NSFW platforms excluded by default** — WMN adult category and Maigret isNSFW platforms filtered; use `--nsfw` to include
- **Hidden output directory fixed** — usernames starting with `.` (e.g. `.rxzikhx.`) no longer create hidden `results/.rxzikhx./` directories
- **80+ additional platforms added to gate-blocked list** — Russian/obscure forums, dead sites, search-page URLs, adult platforms, login gates
- **Duplicate results fixed** — same platform from WMN+Sherlock+Maigret no longer counted multiple times

### New Flags
- `--nsfw` — include adult/NSFW platforms (excluded by default)

---

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
