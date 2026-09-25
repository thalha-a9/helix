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
- **Real accounts no longer purged by the redirect check** — redirects are now judged against the URL actually requested, so API-probed platforms (Chess.com, Bluesky) were being purged on every hit. Same-site subdomain moves that keep the username (`en.gravatar.com` → `gravatar.com/name`, `name.tumblr.com` → `www.tumblr.com/@name`) are allowed. Twitter/X and Threads now point at `x.com` and `threads.com`.

- **Control probe** — every hit is re-checked with a random username that cannot exist; a platform that "finds" it too is discarded as unverifiable. Catches login walls and catch-all pages automatically — the cause of the Facebook, Instagram and Steam false positives seen on a live scan of a made-up name. On a full live scan it removed PyPi, Packagist and Apple Developer (Sherlock). Maigret engine leads get a page-similarity version of the same check. `--no-control` disables it.
- **Database entries validated before scanning** — WhatsMyName, Sherlock and Maigret definitions (including cached copies) must have a real http(s) URL with `{username}` and no other placeholder, and non-empty evidence for their detection method. Maigret's 8 unusable entries (`{username}.com`-style domain checks, Rutracker's unfilled `{urlMain}`) are now skipped instead of requested.
- **`--all`** — builtin + WhatsMyName + Sherlock + Maigret databases in one flag (~6,000 sites).
- **Steam false positive fixed** — Steam counted any page lacking its not-found text as a profile, so rate-limit and error pages read as "found" (a made-up name was reported on a live scan). It now requires the profile data every rendered profile embeds.
- **Full-database scans hold up** — aiohttp silently switches to the aiodns resolver when it is installed (maigret pulls it in), which timed out under thousands of lookups; Helix now pins the system resolver with a DNS cache. Scans over 200 sites make one 10-second attempt per site instead of three 14-second ones, so dead hosts no longer dominate the run time.
- **Clean Ctrl-C** — interrupting a large scan printed one `Task was destroyed` line per pending probe (thousands); it now exits with a single line. Per-site DNS/socket failures no longer print tracebacks — they are already recorded as that site's error.

### Intelligence
- **#20 Robin dark-web module** (`--darkweb`, alias `--robin`) — Ahmia .onion search for the subject's username, confirmed emails and corroborated real name. Hits must contain the exact term (a longer handle such as `janeroe2000` is dropped), and a page that is neither results nor Ahmia's empty state is reported as "not checked", never as "nothing found". With `--ai`, results go to the model as numbered sources; statements that cite no real source are discarded.
- **#21 / #22 Breach sweep** (`osint/adapters/breachdb.py`) — XposedOrNot plus Have I Been Pwned (`HIBP_API_KEY`), merged per breach. One plain-language verdict per email with data classes, date range, the sources checked and when. HIBP spam-list and fabricated entries are ignored. Unreachable sources are listed as not checked, never read as clean. **Fixes `--breach` never reporting a breach**: it called XposedOrNot's `check-email` endpoint but parsed the `breach-analytics` response shape.
- **#23 Relationship map** — employers, former employers, organisations, family and mentioned accounts, taken only from what the subject's own profiles declare (bio, GitHub company field, public GitHub orgs). Each edge cites its source and quote; its confidence never exceeds the declaring account's identity confidence, and HIGH needs two independent accounts. In the console, graph, HTML report, JSON, CSV and TXT.
- **Approved-subject gate** — breach and dark-web lookups only use analyst-supplied identifiers and those from accounts corroborated as the subject's (identity MEDIUM/HIGH); held-back identifiers are listed with the reason.
- Breach, dark-web and relationship findings appear in every writer: JSON, CSV, TXT, HTML report and graph.

### Security
- **Graph XSS** — scanned profile text (e.g. an `og:title` containing `</script>`) was inlined unescaped into the graph's script block and could run script when the graph was opened. The inlined JSON is now escaped.
- TLS verification re-enabled in the GitHub deep recon, Wayback, crt.sh, paste, avatar-hash and breach modules, which still passed `ssl=False` after #1.
- GitHub emails, organisations and CT domains are HTML-escaped in the report.

### Graph
- **Graph rendered blank** — the D3 script's SRI `integrity` value was a malformed SHA-512 digest (63 bytes), so every browser refused to load D3. Now pinned to `d3@7.8.5` with its correct digest, taken from the npm registry tarball.

### Testing
- The suite runs without `pytest-asyncio` installed (e.g. system Python on Kali, where PEP 668 blocks pip).
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
