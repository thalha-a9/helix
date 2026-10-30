# Helix Changelog

## v3.6.0 (2026-10-30)

### Added
- `--fediverse`: 3,925 Mastodon, Misskey, Lemmy and PeerTube servers, each its own website with its own users, checked through each server's standard user lookup. Every server passed a live test (an existing account found, two made-up names not) and had at least one active user a month. Included in `--all`, which now checks 11,988 sites; servers another database lists are skipped; 14 adult servers only with `--nsfw`. `tools/update_fediverse.py` rebuilds the list.
- Docker image, `ghcr.io/thalha-a9/helix`, for linux/amd64 and linux/arm64 with every module included: `docker run --rm -v "$PWD:/data" ghcr.io/thalha-a9/helix -u USERNAME`. Published on each release tag, or by hand from the Actions tab.
- Issue forms for false positives, broken sites, bugs, new sites and feature ideas, plus `CONTRIBUTING.md` and `SECURITY.md` (private vulnerability reports).

### Changed
- README: leads with verified username checking across 8,305 sites, shows the laptop timings next to the fast-link run, and recommends `--concurrency 150` to start.
- Release workflow: artifact actions moved to their Node 24 versions, and a release can be started from the Actions tab (Run workflow), which creates the tag and starts the Docker publish.

### Fixed
- False positive on sites that read only the leading number of a username as a member id: forum.quik.ru showed member #4's profile for the made-up name "4tj4jneu4byr", and the control names, starting with other digits, got a clean 404. The second control name now keeps the leading digits, so such a site "finds" it too and is dropped. Real usernames that start with digits are still found on ordinary sites.

## v3.5.0 (2026-10-29)

### Added
- Control probe: every hit is re-checked live against two usernames that cannot exist, shaped like the one being searched. Sites that "find" them are dropped. `--no-control` turns it off.
- `--all` to scan the builtin, WhatsMyName, Sherlock and Maigret databases together (8,305 sites as of this release).
- `--maigret-engine` to use the installed Maigret engine as a lead source; every lead is re-checked by Helix.
- Identity confidence (HIGH / MEDIUM / LOW) for every finding, with the evidence behind it (#24).
- `--location` to flag profiles that state a conflicting location (#17).
- `--proxy` and `--tor` for all traffic, with remote DNS, a check that the proxy is reachable before scanning, and credentials redacted from output (#12).
- `--breach` sweep against XposedOrNot and Have I Been Pwned (`HIBP_API_KEY`) (#21, #22).
- `--darkweb` / `--robin`: Ahmia search for confirmed identifiers, with optional cited AI analysis (#20).
- Relationship map built only from what the subject's own accounts declare (#23).
- Approved-subject gate: breach and dark-web lookups only use identifiers tied to the subject.
- `--save-pages` keeps the exact page behind every reported account, hashed and timestamped, with an `index.html`. `--verify-pages DIR` checks them.
- `--record-attempt` writes sealed evidence of a scan; `--verify-evidence` checks it, including saved pages.
- `--concurrency N`, with a timeout retry pass when the link is overloaded.
- Reproducible benchmark harness in `bench/`, with published results.
- `helix-osint` command next to `helix` (on Arch the `helix` name belongs to the Helix editor).
- Release workflow (tag to PyPI via Trusted Publishing) and a BlackArch PKGBUILD.
- Test suite (1,432 tests) and CI on Python 3.9, 3.11, 3.12, 3.13 and 3.14 (#9).

### Changed
- Removed `wd.sh` (a Waydroid install script committed by mistake) and `osint/adapters/breach_adapter.py` (replaced by `breachdb.py`).
- Search pages and adult sites are no longer scanned by default; `--nsfw` brings adult sites back, including holehe's adult-site modules.
- Pages judged only by status code or by a missing "not found" text must name the exact user.
- Instagram and TikTok need positive profile evidence; GitLab and Keybase are checked through their APIs; Facebook and Threads are never reported (same login wall for every name).
- `--phash` uses a stricter match threshold and ignores default avatars and site-wide images.
- `--crt` reports domains named after the username (as leads) and domains on certificates that list the email.
- `--email-permute` results are leads only and never count as email confirmation.
- The version lives only in `osint/__init__.py`.
- README rewritten around what Helix verifies, with measured numbers.

### Fixed
- Python 3.9 failed at import because of a `bytes | None` annotation.
- Response bodies were cut short, so detection judged partial pages.
- `--holehe` never ran (wrong API use and an import name clash).
- `--breach` never reported a breach (wrong response shape).
- `--crt` never found anything (crt.sh does not support the pattern it used).
- `--nsfw` did nothing: the WhatsMyName filter read the wrong field and the Sherlock and Maigret caches dropped the adult flag.
- The investigation report lost every profile when `--crt` was used, and never listed email accounts or unreachable sources.
- A dead proxy made every scan read "0 accounts found".
- Steam, GitLab and several bio-link patterns produced false positives.
- Redirect handling purged real accounts on API-checked platforms.
- `--tor` leaked DNS lookups for curl-based requests.
- Wayback "last seen" and capture counts were wrong; `--paste` and `--wayback` reported outages as "nothing found".
- Large graphs settled off-screen; the graph rendered blank because of a malformed SRI hash.
- Sites with response headers over 8 KB failed outright.
- `--output` accepted sibling directories whose names share a prefix.
- Ctrl-C on a large scan printed thousands of lines.
- `--ai` failed for every provider: all three default models had been retired. It now uses Claude Sonnet 5.5 and the free Nemotron 3.5 Super, with Nemotron 3.5 Lightning as a fallback (OpenRouter, NVIDIA). It turns Nemotron's reasoning off (with it on, the answer never fit), tries the next model when one is busy or gives no usable answer, shows the provider's reason when a call fails, and `HELIX_AI_MODEL` picks a model.
- `--ai` purged real accounts: its prompt rejected any profile whose title was only the site name ("TikTok", "VK"), which many sites use for every profile. It now only removes login walls, error pages and bot checks, since every result has already passed the control probe.
- Page titles with HTML entities (Instagram's "&#064;", "&#x2022;") were not decoded, so names in them were missed.
- `--paste` relied on psbdmp.ws, which shut down; it now says Pastebin text search is unavailable and where Pastebin accounts are covered. Errors are no longer cut at 60 characters.
- The scan printed the first name found on any profile as the subject's "real name" (torvalds on Medium is Patricia Torvalds). It now lists each name with the profiles that state it and warns when they differ.
- A removed Patreon account (200, "Removed | Patreon") was reported as found.
- `--wayback` looked up only some profile categories and only the exact current URL; it now covers every category (25 profiles per scan) and the trailing-slash and twitter.com addresses.
- X detection used not-found text that X now draws with JavaScript.
- The saved-pages index squeezed hashes to one character per line on narrow screens.
- Three tests failed when the checkout path contained spaces.

### Security
- Avatar downloads only go to public addresses, checked on every redirect and pinned at connect time (SSRF).
- Avatars are decoded as JPEG/PNG/GIF/WebP only, with size limits; the extras require Pillow 13 on Python 3.11+.
- Every third-party string is escaped in the graph, report and saved-pages index, and links are http(s) only.
- CSV cells that start with `=`, `+`, `-` or `@` are neutralised.
- Terminal output passes only Helix's own colour codes.
- TLS verification is on in every module.

## v3.4.0 (2026-06-05)

### Security Fixes (14 issues resolved)
- **#1** SSL/TLS verification now enabled by default (`ssl=True`): was globally disabled
- **#2** `--output` path sanitized with `os.path.realpath()`: prevents directory traversal
- **#3** Sherlock integrity validation: response must be dict with 10+ keys before use
- **#4** Gravatar email hash changed from MD5 to SHA256
- **#5** Dependencies pinned with version ranges in requirements.txt
- **#7** `KeyboardInterrupt` no longer swallowed by bare `except` blocks
- **#8** `_check_deps()` moved to `main()`: no longer calls `sys.exit()` at import time
- **#10** XSS fixed in HTML report and graph: all user-controlled data HTML-escaped
- **#11** D3.js loaded with SRI integrity hash and `crossorigin="anonymous"`
- **#13** `install.sh` stale repo name `osint-grapher` replaced with `helix`
- **#14** HTTP response body capped at 512KB to prevent memory exhaustion

### False Positive Fixes
- **Default avatar filtering**: pHash no longer reports matches when 3+ platforms share the same hash (Mastodon grey silhouette, CDN placeholders)
- **NSFW platforms excluded by default**: WMN adult category and Maigret isNSFW platforms filtered; use `--nsfw` to include
- **Hidden output directory fixed**: usernames starting with `.` (e.g. `.rxzikhx.`) no longer create hidden `results/.rxzikhx./` directories
- **80+ additional platforms added to gate-blocked list**: Russian/obscure forums, dead sites, search-page URLs, adult platforms, login gates
- **Duplicate results fixed**: same platform from WMN+Sherlock+Maigret no longer counted multiple times

### New Flags
- `--nsfw`: include adult/NSFW platforms (excluded by default)

---

## v3.3.0 (2026-06-02)

### New Features
- **Email permutation engine** (`--email-permute`): generates likely email addresses from username + extracted real name, optionally checks each with holehe
- **PDF/HTML investigation report** (`--report`): standalone shareable report with all findings, Wayback data, GitHub intel, avatar matches, CRT domains. PDF output requires `pip install weasyprint`
- **Real name extraction**: automatically extracts display names from OG-verified profiles (e.g. "Mohammad Aqib" from Dribbble) and uses them for email permutation
- **Maigret adapter** (`--maigret`): loads soxoj/maigret database at runtime, adds 2000+ platforms with sophisticated presenceStrs/absenceStrs detection
- **Sherlock adapter fixed**: updated to new `sherlock_project/resources/data.json` path (v0.16.0 repo restructure)

### False Positive Fixes (7-layer verifier v3.2 -> v3.3)
- **Registration API trap**: 41 URL patterns now blocked pre-request in WMN adapter. These return HTTP 200 to mean "username is FREE", not "profile exists" (WordPress.org, Scratch, Quizlet, BoardGameGeek, Duolingo, TryHackMe, BodyBuilding.com, Arch Linux GitLab, visnesscard, TAPiTAG, Známija GraphQL, and more)
- **Dead host pre-filter**: 35 dead/parked hostnames blocked before any HTTP request (taringa.net, lor.sh, hiberworld.com, chatango.com, wego.social, codeproject.com, and more)
- **Login-gate blocked hosts**: 40+ platforms that always redirect to login/CAPTCHA regardless of profile existence (PayPal.me, Tinder, Vivino, Magix, Flightradar24, Bentbox, igromania, 3DNews, etc.)
- **Soft-404 content detection**: 45+ "not found" strings checked in page body before accepting a result
- **Search-page URL blocking**: OP.GG, Scribd search, Carmasters search, and 10+ other search pages that return results for any query
- **Sherlock false positives**: pr0gramm, Anilist, Apple Discussions, archive.org, mercadolivre, hashnode, authorstream, cssbattle, dailymotion, kaskus, Kik, splice, academia.edu added to gate list
- **patriots.win**: "Error: invalid user" served as 200 OK, now blocked
- **graph.py crash**: fixed `int64` not JSON serializable (numpy type from phash distance values)

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

## v3.2.0 (2026-05-31)

### New Features
- **7-layer heuristic false positive engine**: complete rewrite of verifier.py
  - L1: WAF/CAPTCHA page detection (12 signatures)
  - L2: Registration API trap (17 URL patterns)
  - L3: Soft-404 content scan (30+ strings)
  - L4: Bad redirect path check (20 paths)
  - L5: Dead/parked site detection (8 hosts)
  - L6: Generic title/login page detection
  - L7: Per-platform username format validation (Twitter/X, WordPress, Scratch, BGG, ArtStation, PyPI, npm)
- **WMN adapter v1.2**: pre-flight filter blocks registration APIs and dead hosts before any request
- **Page text passthrough**: checker now stores response body slice for verifier content-based layers
- **Maigret adapter**: initial implementation

### Bug Fixes
- Removed `_page_text` from JSON report output (internal field only)
- Version string consistency across helix.py, pyproject.toml, argparse

---

## v3.1.0 (2026-05-28)

- Initial v3 release with async engine, D3.js graph, WMN/Sherlock adapters
- pHash avatar matching
- Recursive bio pivot
- Wayback Machine module
- GitHub deep recon
- Certificate transparency (crt.sh)
- Paste intelligence (Gist + Pastebin)
- AI verification layer (Claude, OpenRouter, NVIDIA NIM)
