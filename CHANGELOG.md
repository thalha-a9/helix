# Helix Changelog

## v4.1.0 (2026-11-11)

### Changes you may notice

1. **The Python package is now `helix_osint`, not `osint`.** Code that imports Helix must change `import osint` to `import helix_osint`, and `from osint.api import scan` to `from helix_osint.api import scan`. The old name is gone, not kept as an alias: `import osint` now fails, or loads a different project if one is installed.
2. **`import helix` no longer works either.** The command line program moved from the top-level module `helix` to `helix_osint.cli`. Code that called `helix.main()` or `helix.run()` should use `helix_osint.cli`.
3. **The module commands changed name with it:** `python -m osint.health` is now `python -m helix_osint.health`, `python -m osint.evidence` is `python -m helix_osint.evidence`.
4. **Nothing changes for the commands.** `helix-osint`, `helix`, the Docker image and `python helix.py` from a source checkout work as before, with the same options and the same output. `python -m helix_osint` is new and does the same.
5. **Files in the repository moved:** `osint/` is `helix_osint/`, and the lists people send pull requests for are now `helix_osint/data/sites.json` and `helix_osint/data/left_out.json`.
6. The left-out list is kept at its old address in the repository too (`osint/data/left_out.json`), identical to the real one, so 4.0.0 installs still pick up new entries. That copy is not installed.

### Fixed
- Helix installed two things at the top level of Python's site-packages: a package named `osint` and a module named `helix`. Both names are too general to belong to one project, and `osint` is another project's name on PyPI, so the two could overwrite each other. Reported by noraj in the BlackArch review. Everything now lives in one package, `helix_osint`, and the wheel holds nothing else. The Maltego transform and the SpiderFoot module import the new name.

## v4.0.0 (2026-11-10)

Measured on 10 Nov 2026 from one cloud data-centre address. Site totals change when the upstream lists change, so each number has its date.

### Changes you may notice

These can change what an existing command prints, what a script reads, or how long a scan takes. Nothing was removed from the command line: every 3.7.0 command still runs.

**Results**
1. **Different accounts for the same name.** About 5,800 Maigret forum and wiki sites are now asked at their real profile address. Expect more accounts than before (`torvalds`: 110 with 3.7.0, 132 now), and a few that were reported before and are not now, because the old address showed a page that was not a profile.
2. **Different profile addresses in reports.** For those sites the `url` in the JSON, CSV and TXT reports changes, for example `https://forum.example/janeroe` is now `https://forum.example/members/?username=janeroe`. A script that matches on addresses needs a look.
3. **Different site totals.** `--all` was 11,663 sites on 4 Nov and is 11,956 on 10 Nov. A few dozen entries that need a POST request or have no address pattern are no longer scanned (they were asked wrongly before), so a few site names disappear.
4. **Answered counts are not comparable with older records.** Older "answered" numbers included thousands of 404s from addresses no profile lives at.

**Scans**
5. **A second attempt runs by default.** Sites that gave no clear answer are asked once more. That is up to about 10% more requests and some extra seconds on a poor connection. `--no-recover` gives the old behaviour.
6. **Sites can be left out.** Sites that are dead or broken on three daily checks are skipped and the scan says how many. The list ships empty in 4.0.0 and fills from the daily check, so the attempted count can drop from one day to the next. `--include-off` scans everything.
7. **Two more small downloads a day.** A scan that downloads the site databases also fetches the switched-off list and the left-out list from the Helix repository, at most once a day each.
8. **Some names are refused.** A username or address on the left-out list stops the scan before any request, with exit code 3. The list ships empty.
9. **Your own site list is read.** If `~/.config/helix/sites.json` (or `$HELIX_SITES`) exists, every scan includes it, ahead of the databases.
10. **The site databases are downloaded again once.** The cache files have new names; the old ones in `~/.cache/helix/` can be deleted.
11. **Some sites get extra request headers** that their database entry lists, and with `curl_cffi` installed about 100 Maigret sites are asked with a browser's TLS fingerprint.

**Output and files**
12. **The sealed record has new fields.** `attempt.purpose` is always there ("not stated" unless `--purpose` is given). `attempt.collector`, `summary.second_attempt` and `database.switched_off` are new, and `counting_rules` has one more entry. The schema name is still `helix.record-attempt.v1`, records made by older versions still verify, and `--purpose` is not required.
13. **The record block at the end of a scan has a new "Purpose" line**, above "Started".
14. **Error texts are more exact.** In the JSON report and the sealed record, `connection_error` can now read `connection_error: host name does not resolve`, `connection_error: invalid HTTPS certificate` or `connection_error: name lookup failed`. A script that tests for the exact text `connection_error` should test the start of the text instead. The reasons in `unanswered_by_reason` gain "host name does not resolve" and "invalid HTTPS certificate".
15. **The JSON report has new keys.** Under `intel`: `purpose`, `watch`, `self_check`, `phone`, `sites_left_out`. A result can carry `recovered`, `verified_by`, `delete` or `shows_phone`. Nothing was renamed or removed.
16. **The hash of the site list changes** (`database.sha256`) even for the same upstream data, because site definitions now carry a known account and, for fediverse servers, a second rule.
17. **The scan output has new lines**: "Asking N site(s) again that gave no clear answer..." and, when sites are left out, a line saying how many.

**For code that imports Helix**
18. `osint.checker.check_username` has two new optional arguments (`recover`, `recover_cb`). `osint.adapters.maigret_adapter._translate` takes the engines as a third argument. `osint.adapters.breachdb.check_identifiers` takes an optional `kind`. Existing calls keep working. The supported way in is now `osint.api.scan`.

### Fixed
- On Python 3.11.2 (the version Debian 12 ships) a scan could finish and then crash while closing its connections, in aiohttp's cleanup of closed SSL connections. Helix no longer turns that cleanup on. Connections are still closed after each request, so large scans stay within the open-file limit. Reported and fixed by @Anzo52 (#25).
- Two thirds of the Maigret database was scanned at the wrong address. 5,870 of Maigret's 8,969 entries give no address of their own, only an engine (XenForo, Discourse, uCoz, MediaWiki, Gitea, GitLab and others) that holds the address pattern and the "not found" texts for every site of that kind. Helix did not read engines and asked `https://site/{username}` instead, which is 404 for every name. Those sites counted as answered and could never find an account. The daily site check found it: 4,398 Maigret sites answered a made-up name but did not find the account Maigret lists for them. Engines are now read, an entry without an address pattern is skipped (never guessed), the API address an entry lists is the one asked, and Mastodon and Lemmy engine sites use Helix's own fediverse rule. Sites proven with a real account went from 2,507 to 6,130 of about 12,000. A scan of `torvalds` the same hour found 110 confirmed accounts with 3.7.0 and 132 with this fix (106 in both; the 26 new ones are mostly forums on those engines).
- The answered count of earlier releases included those wrong-address sites. The 4 Nov record (11,663 attempted, 10,134 answered) is a true count of clear answers, but several thousand of them were "no such page" from an address no profile lives at. Records from this release on do not have that flaw.
- Sherlock: the probe address an entry lists (`urlProbe`) is now the one asked, every "not found" text counts (Archive.org lists three; only the first was read), and entries that need a POST are skipped instead of being asked with a GET. WhatsMyName entries that need a POST are skipped for the same reason. Request headers an entry lists are sent.

### Added
- **The daily site check** (`python -m osint.health check`, [docs/SITE_CHECK.md](docs/SITE_CHECK.md)). Every site is asked for a made-up name and, where an account is known to exist there, for that account. Each site is filed as proven, answers, blocked, dead, broken or unknown. A site that is dead or broken on 3 checks in a row is switched off: scans leave it out, say how many were left out, and seal the count into the record. The first working check switches it back on. A blocked site (bot check, 403, rate limit) is never switched off. `--include-off` scans everything. The check writes a status page (one HTML file) and the list scans read; a daily GitHub Actions job publishes both.
- Known accounts for the daily check: the ones the Maigret, Sherlock and WhatsMyName databases list, one for 52 of the 56 built-in sites, and for fediverse servers the account each server names itself (its contact or admin).
- **A second attempt** for sites that gave no clear answer: another rule for the same site where its definition lists one, then the same request after the pause a rate limit or server error calls for, then (with `curl_cffi`) a browser's TLS fingerprint for bot checks and refusals. A result is replaced only by a clear answer, and a hit found this way goes through the whole control probe, read by the rule that found it. `--no-recover` skips it.
- **WebFinger as a second rule for every fediverse server.** Hosting companies rate-limit the lookup API for a whole network at a time; WebFinger still answers. When the control probe itself is blocked part of the way, it is run again in full by the second rule. On the full list, 167 to 175 sites per scan were answered this way.
- **`--learn URL`**: Helix works out a site's rule from its profile address, proves it with the control probe, and saves the site to your own list as one line ([docs/LEARN.md](docs/LEARN.md)). Your list is read first by every scan; `osint/data/sites.json` is Helix's own list for contributed lines.
- **`--watch`**: a hash-chained history per username. Each scan says what is new, removed or changed. "Removed" needs the site to say "no such user" clearly; a site that did not answer is "not checked". `--verify-watch` re-checks the chain.
- **`--me`**: check yourself. Scans every source for your username and, with `-e`, the breach lists, then shows where to delete each account (deletion pages from JustDeleteMe) and writes `<name>_my_accounts.html` and an erasure request naming GDPR Article 17 and section 12 of India's DPDP Act.
- **`--purpose` and `--collector`** are sealed into the evidence record. Without a purpose the record says "not stated".
- **The left-out list**: anyone can ask that a username or address is never looked up. The list holds slow-hash tokens, not names; a listed name is refused before any request, and pivots and permutations skip it. `--left-out-token NAME` prints the token to send ([docs/LEFT_OUT.md](docs/LEFT_OUT.md)).
- **A Python API** (`osint.api.scan`, `scan_sync`): the same scan as the command line, returned as one dictionary and printing nothing.
- **`--serve`**: a local web page for people who do not use a terminal, in English, Hindi, Spanish, Arabic, Portuguese and Russian (the five translations have not yet been checked by native speakers), with a small HTTP API. It listens on this computer only, needs a token, and refuses requests for another host name.
- **Maltego and SpiderFoot** integrations in `integrations/`: a local transform and a module, both calling the library. Tested against the documented formats, not yet inside either tool.
- **`--phone NUMBER`**, opt-in only and never part of `--all`. It needs `--purpose`. Three parts: what the number itself says (country, region, carrier at issue, kind of line), worked out offline with the optional `phonenumbers` package (`pip install helix-osint[phone]`); whether the accounts found for `-u` show the number, read from the pages already received; and with `--breach`, whether it is in known breaches, asked of Have I Been Pwned (needs `HIBP_API_KEY`; this request follows its documentation and has not yet been run against the real service). Nothing is sent to the number: no sign-up, login or reset form is asked and no messaging app is checked. Reports hide the middle digits unless `--show-number` is given, and the sealed record never holds the number in full. `--me` takes `--phone`.
- [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md): what Helix is and is not for, and the GDPR and India's DPDP Act in plain words.
- [docs/EVIDENCE_SPEC.md](docs/EVIDENCE_SPEC.md): every field of the scan record, the saved pages and the watch history, how each is hashed and checked, and how they relate to the Berkeley Protocol, with what Helix does not capture stated.
- The sealed record names dead host names ("host name does not resolve") and broken certificates ("invalid HTTPS certificate") instead of "connection error", and counts second attempts under `summary.second_attempt`.

### Measured
- Full list, made-up name, before the address fix: 10,580 of 12,111 sites answered (87.4%) without the second attempt, 10,886 (89.9%) with it, in 326 s and 316 s.
- Full list, made-up name, after the address fix: 10,661 of 11,956 answered (89.2%) in 359 s, 0 accounts.
- The daily site check, three times on 10 Nov: 9,504 to 9,524 of 11,956 sites proven with a real account (79.6%), about 1,150 more answer a made-up name, about 480 blocked, 565 dead, 157 broken. 654 sites were dead or broken in all three.
- Full list with those 654 left out, made-up name: 10,652 of 11,302 answered (94.2%) in 217 s, 0 accounts. The shipped switched-off list is empty: a site is switched off after failing on three separate days, and that record starts when the daily job runs.
- Speed, one run each, same machine and hour, made-up name ([bench/SPEED.md](bench/SPEED.md)): Helix 11,302 sites in 217 s (52 a second), Maigret 0.6.6 8,245 sites in 147 s (56 a second), Sherlock 0.16.2 about 480 sites in 68 s. Maigret was slightly faster per site; Helix checked the most sites. Sherlock reported 8 accounts for the made-up name, Helix and Maigret none.
- The sealed release run with 4.0.0 (made-up name, switched-off list empty): 10,663 of 11,956 answered (89.2%) in 290.5 s, 0 accounts. Record in `bench/results/2026-11-10_release_4.0.0_madeup/`, fingerprint `18fe1e92...059a61`.
- What still does not answer from a data-centre address, of 11,956: about 290 bot-check pages, 185 timeouts, 160 HTTP 403, 155 sites whose rule finds made-up names, 110 invalid certificates, 84 hosts the test network's own proxy refused. A real browser did not get past the bot checks from that address either (4 of 60 tried), so no browser was added.

## v3.7.0 (2026-11-05)

### Fixed
- The same profile address listed by two databases was checked twice and, when it existed, reported twice: `dev.to/{username}` came from the built-in list and from Sherlock, `x.com/{username}` likewise, and 270 such repeats sat in `--all`. An entry whose profile address is already listed is now skipped (the built-in or earlier one is kept), and the loader says how many. WhatsMyName entries that probe an API now show the profile page people open (and still probe the API), so they are recognised too. `--all` now checks 11,663 sites, each once, instead of 11,963 entries.
- GitHub's site-wide share images (on every gist and repository page) were not recognised as generic, so with `--phash` two people's gist pages could have read as "the same picture". They are now skipped like other default images, and that filter has tests.
- holehe's rate-limited sites are named as such in a sealed email record, not "other error".
- The sealed record said every account was checked against "two impossible usernames"; since 3.6.2 it is at least three. The record now stores how many (`attempt.controls`) and the end-of-run block says it.
- `--permutations` without anyone to answer its question no longer runs the next line onto the prompt.
- A scan where sites could not be reached ended with "None found", which reads like "this person has no accounts". With Tor not running, all 56 built-in sites failed and the scan still said "None found". Every scan now says how many sites gave no clear answer and why (bot checks, timeouts, proxy or Tor failures and so on), and when none answered it says nothing was checked. A failing SOCKS proxy or Tor is named as such instead of "other error".

### Added
- LeakCheck as a third `--breach` source, free and without a key. It is sent the first 24 characters of the address's SHA-256 hash, never the address, and returns breach names and dates only. Its breaches merge with the same ones from XposedOrNot and HIBP ("LinkedIn.com" and "LinkedIn" count once), and the data types it lists cover all its matches, so they are shown once rather than pinned on each breach. Requests are paced to its limit of one a second. Like the other breach sources it runs only with `--breach`, after the accounts are found and graded, and a test checks that a scan reports the same accounts and grades with and without it.

### Changed
- README and `--help` now explain `--controls`, `--permutations` (about 45 variants, each a full scan), `--providers`, `--output`, `--no-browser`, the database download timeouts and everything `--nsfw` covers.

## v3.6.2 (2026-11-02)

### Fixed
- False positives for short usernames on sites that accept any short name and refuse longer ones, found by a reviewer. The made-up names behind every hit were padded to 12 random characters so they could not collide with a real account, so a site that "finds" every name up to 11 characters and answers longer ones with 400 "invalid" (or a 404 from a route that only matches short names) gave them a clean "not found", and any short name was reported as an account. A short name now also gets a made-up name of exactly its length. When a site "finds" that one too, the hit is reported as **unconfirmed** with the reason (any short name works there, or that name is taken), not as an account and not silently dropped. The benchmark now includes both kinds of site: on 1,000 mock sites the old code reported 42 false positives, the new code 0, with every real account still found. Measured live on all 11,963 sites: for `jack` (4 letters), 40 of the 960 sites that reported it, all large ones such as Chess.com, Docker Hub, Minecraft and Roblox, are now unconfirmed, because random 4-letter names are taken there; for `torvalds` (8 letters), none. The JSON report lists unconfirmed sites with their own count.

### Added
- `--controls N`: how many made-up names every hit is checked against (default 3, at least 3). More catch sites that answer only some names; use it when a result must be defended.
- `--record-attempt` seals an email scan (`-e`) too. It writes its own evidence and sites files (`<label>_email_*` when a username is scanned in the same run), so the username record stays exactly as before, and `--verify-evidence` checks it. The end-of-run block shows the address and says how many sites have an account for it; it does not claim the fake-username control probe, which email checks do not run. Before, an email scan with `--record-attempt` wrote no record.

## v3.6.1 (2026-10-31)

### Fixed
- False positive on Olx.pl, found by a reader: a made-up username was reported as an account. Maigret lists two "not found" texts for Olx.pl and Helix read only the first, so a generic page carrying the second passed. Every "not found" text of a Maigret entry now counts (65 entries list more than one). Olx.pl user pages are keyed by seller ids, so a username match there was never evidence anyway. Checked against 635 real hits for `jack` and `torvalds`: none lost.
- Maigret entries that take an account id rather than a username (VK, Steam, Yandex ids and similar) are skipped instead of being requested with a username. That is 25 entries, so `--all` now checks 11,963 sites. Three full scans of new made-up names with this release: 0 accounts each.

## v3.6.0 (2026-10-30)

### Added
- `--fediverse`: 3,925 Mastodon, Misskey, Lemmy and PeerTube servers, each its own website with its own users, checked through each server's standard user lookup. Every server passed a live test (an existing account found, two made-up names not) and had at least one active user a month. Included in `--all`, which now checks 11,988 sites; servers another database lists are skipped; 14 adult servers only with `--nsfw`. `tools/update_fediverse.py` rebuilds the list.
- Docker image, `ghcr.io/thalha-a9/helix`, for linux/amd64 and linux/arm64 with every module included: `docker run --rm -v "$PWD:/data" ghcr.io/thalha-a9/helix -u USERNAME`. Published on each release tag, or by hand from the Actions tab.
- Issue forms for false positives, broken sites, bugs, new sites and feature ideas, plus `CONTRIBUTING.md` and `SECURITY.md` (private vulnerability reports).

### Changed
- README: leads with verified username checking, shows the laptop timings next to the fast-link run, and recommends `--concurrency 150` to start.
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
