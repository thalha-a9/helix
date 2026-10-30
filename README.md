<div align="center">

```
  ██╗  ██╗███████╗██╗     ██╗██╗  ██╗
  ██║  ██║██╔════╝██║     ██║╚██╗██╔╝
  ███████║█████╗  ██║     ██║ ╚███╔╝
  ██╔══██║██╔══╝  ██║     ██║ ██╔██╗
  ██║  ██║███████╗███████╗██║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝
```

### Decode the digital DNA of any identity

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.5.0-00ff88?style=flat-square)](https://github.com/thalha-a9/helix/releases)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=flat-square)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-56%20builtin%20%7C%208%2C305%20with%20--all-a78bfa?style=flat-square)](https://github.com/thalha-a9/helix)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-reproducible%20%7C%200%20false%20positives-00ff88?style=flat-square)](bench/README.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/thalha-a9/helix/pulls)

**Helix** is an open-source username checker for OSINT. It checks a username<br>
across **8,305 sites** (the Sherlock, WhatsMyName and Maigret databases combined)<br>
and re-checks every hit live before reporting it: a made-up username comes back with **0 accounts**.<br>
Then it shows which accounts belong to the same person, in an interactive graph you can explore and export.

*"Finding accounts is easy. Proving them is the job."*<br>
**Thalha Ahmed**, creator of Helix | [@thalha-a9](https://github.com/thalha-a9)

[**Quick Start**](#quick-start) | [**Features**](#what-makes-helix-different) | [**Modules**](#intelligence-modules) | [**Graph**](#the-graph) | [**Install**](#installation)

</div>

---

## Why Helix?

Most username checkers answer one question, *"Does this username exist on Platform X?"*, and leave you to sort the real hits from the false ones.

Helix answers it across 8,305 sites with every hit verified, then answers the harder one: **"Which of these accounts belong to the same person?"**

It extracts cross-platform links the account holders declare, matches identical profile pictures by perceptual hash, infers timezone from commit patterns, discovers domains via certificate transparency, and plots every relationship as a glowing edge in a browser-based network graph, all in a single command.

```bash
pipx install helix-osint
helix-osint -u johndoe --all                    # 8,305 sites, every hit verified
helix-osint -u johndoe --phash --pivot --crt    # plus avatar matching, pivoting and domains
```

---

## What Makes Helix Different

Helix builds on Sherlock, WhatsMyName and Maigret. With `--all` it scans
their site databases together (8,305 sites on 29 Oct 2026, with adult sites
and search pages left out; `--nsfw` adds adult sites back). What it adds is
what happens after a site says "found":

| | What Helix does | Why it matters |
|---|---|---|
| **Live verification of every hit** | Each hit is re-fetched, and two usernames that cannot exist are requested from the same site at the same moment. The hit is kept only if it reproduces and both impossible names get the same clear "no such user" | Login walls, catch-all pages and changed markup are caught automatically, on every site, with no per-site tuning |
| **A measured, reproducible false-positive rate** | 0 false positives on made-up names across the whole database, in a sealed rehearsal anyone can verify (8,305 sites) and in every earlier full run, with the harness and run records in [`bench/`](bench/README.md) | A number anyone can re-run, not a promise |
| **Identity confidence per finding** | HIGH / MEDIUM / LOW from independent evidence: avatar match, declared cross-link, email, real name, location. A username match alone is never above LOW | "The account exists" and "the account is your subject" are reported separately |
| **Perceptual avatar matching** | The identical picture on two accounts links them (`--phash`); platform defaults and site-wide images are ignored | Corroboration that does not depend on the username |
| **Declared-only relationships** | Employers, organisations and family taken only from what the subject's corroborated accounts state, each with its source and quote | Nothing inferred from shared surnames or followers |
| **Approved-subject gate** | Breach and dark-web lookups only send identifiers the analyst supplied or that come from corroborated accounts | Third parties never receive a stranger's data |
| **Proof of every page** | `--save-pages` keeps the exact response behind each reported account, hashed and timestamped, and the evidence file seals the list | An editor or a court can see what the profile said when it was found |
| **One standalone graph file** | Accounts, cross-links, avatar matches, breaches and relationships in a single HTML file, no server | Hand it to someone and it opens |

Where other tools are stronger: SpiderFoot has far more data-source modules and a web UI built for long
investigations. Maigret extracts more profile fields per site and searches
recursively on the IDs it finds. Maltego has commercial data feeds and a
mature graph workspace. Helix is the one to reach for when a wrong account in
the report is the expensive mistake.

---

## Intelligence Modules

### Always On
- **Local Heuristic Verifier**: Zero-dependency false-positive engine. Scores every result across 8 signals (WAF pages, generic titles, login redirects, homepage redirects). Runs before anything else, every single scan.

### Core Flags
| Flag | What it does |
|---|---|
| `--wmn` | Loads WhatsMyName database at runtime: **~590 platforms** after unsafe entries are filtered out |
| `--maigret` | Loads **Maigret** database at runtime: sophisticated detection with `presenceStrs`/`absenceStrs`, 24h cached |
| `--all` | Full coverage in one flag: builtin + WhatsMyName + Sherlock + Maigret databases (8,305 sites on 29 Oct 2026, adult sites and search pages excluded; the upstream databases grow), every hit checked by the control probe |
| `--concurrency N` | Probes in flight at once (default 20 to 60, scaled to the scan size; max 1,000). Raise it only on a fast, direct link: live, 250 in flight made 1,302 healthy sites time out on an ordinary connection. Sites that time out get one calm retry either way, and the end of every scan says how many sites answered |
| `--save-pages` | Keeps the exact page received for every reported account: the raw bytes, response headers, the URL it ended on and the UTC time, each hashed with SHA-256, in `<name>_pages/` with a browsable `index.html`. Proof of what a profile showed at that moment, even if it is deleted later. Pages are saved as text so they cannot run scripts. For sites checked through an official API, the saved page is the API's answer. `--verify-pages DIR` re-checks every file |
| `--record-attempt` | Writes sealed evidence of the scan, for a witnessed test, an audit or a published result: UTC start and finish, the exact site database and its SHA-256, the outcome for every site, and a fingerprint of the whole file, printed at the end so a screen recording can show it. `--verify-evidence FILE [SITES]` checks it |
| `--maigret-engine` | Runs the installed **Maigret engine** (`pip install maigret`) as a lead source: every hit is re-fetched and verified by Helix before it is reported. `--maigret-top N` sets how many sites it checks (default 500) |
| `--sherlock` | Loads Sherlock's database at runtime: **~440 platforms**, cached 24h locally |
| `--pivot` | **Recursive alias pivot**: follows handles the account holder declares (Keybase proofs, profile links) and scans them, up to 4 hops deep. Pivot results are leads about the alias, verified like any scan |
| `--phash` | **Perceptual avatar hash**: matches the *same picture* used on two accounts (a different photo of the same person will not match). Platform defaults, site-wide share cards and blank images are ignored |
| `--wayback` | **Wayback Machine**: when each found profile was first and last archived, in how many months, and the bio of the earliest capture (emails / @handles in it listed as leads; a username can change hands) |
| `--crt` | **Certificate Transparency**: domains on certificates that list the subject's email, plus domains named exactly after the username (leads only; anyone can register a name). crt.sh outages are reported as not checked |
| `--paste` | **Paste Intelligence**: public Gists of github.com/&lt;username&gt;. Pastebin text search has had no free source since psbdmp.ws shut down (2026); Pastebin *accounts* are covered by `--sherlock`, `--maigret` and `--all`. Unreachable sources are reported as not checked |
| `--breach` | **Breach sweep**: every confirmed email against XposedOrNot, plus Have I Been Pwned when `HIBP_API_KEY` is set. Per-email verdict: which breaches, what was exposed, date range, which sources were checked and when (e.g. *"x@y appears in 7 breaches (2012 to 2024), passwords exposed in 5"*). A source that could not be reached is reported as not checked, never as clean. Metadata only, no credentials |
| `--darkweb` / `--robin` | **Robin dark-web leads**: Ahmia .onion search for the username, confirmed emails and (when corroborated) real name; only hits that contain the exact term are kept. Includes the breach sweep. With `--ai`, the results go to the model as numbered sources and only statements that cite them are kept |
| `--holehe` | **Deep email scan**: which of ~120 sites the address is registered on (holehe). Modules that would send the target a password-recovery email are skipped. Rate-limited sites are reported as not checked, never as "not registered". With `--email-permute`, accounts found for *guessed* addresses are listed as leads and never count as email confirmation |
| `--ai` | **AI false-positive filter**: second verification pass via Claude, OpenRouter (free), or NVIDIA NIM (free) |

### Auto-Triggered
- **Relationship map**: built from what the subject's own accounts *declare*: employers and former employers ("engineer at Globex", "ex-Initech", GitHub company field), organisations (public GitHub orgs, "maintainer of ..."), family members named by handle ("my wife @...") and accounts the bio mentions. Never inferred from shared surnames, followers or co-occurrence. Only accounts corroborated as the subject's (identity MEDIUM/HIGH) are read: a bio on an account that merely shares the handle may be a stranger's, so those declarations are counted but not mapped. Each edge carries its source, quote and a confidence that can never exceed the declaring account's; two independent accounts are needed for HIGH. Shown in the console, graph, report, JSON, CSV and TXT
- **Approved-subject gate**: breach and dark-web lookups send identifiers to third parties, so only analyst-supplied identifiers (`-u`, `-e`) and those from accounts corroborated as the subject's (identity MEDIUM/HIGH) are queried. Anything held back is listed with the reason
- **GitHub Deep Recon**: runs automatically when a GitHub profile is found, and is labelled with that account's identity grade: until it is corroborated, the facts may describe someone else who has the same handle. Extracts real emails from public commits (filters noreply), org memberships, language stats, npm packages, and infers timezone from commit timestamp distribution (requires >=15 commits for confidence)

---

## The Graph

The HTML output is a standalone zero-dependency interactive network, no server needed, just open in a browser.

```
White pulsing node        Username root
Amber pulsing node        Email root
Amber/orange nodes        Pivot-discovered aliases
Green solid edges         Cross-links the account holder declared (Keybase proofs, profile links)
Pink dashed edges         The same picture on both accounts (perceptual hash)
Red / violet nodes        Breach exposure / dark-web leads (leads, not proof)
Amber dashed edges        Email-matched platforms
Green ring on node        High confidence (OG meta validated)
Blue ring on node         Medium confidence
```

**Controls:** drag nodes | scroll to zoom | click node to open profile | hover for tooltip (confidence, og:title, cross-link partners, bio-extracted alias details) | search | not-found overlay | labels | SVG export | filter by confidence

---

## Quick Start

```bash
pipx install helix-osint          # or: pip install helix-osint
helix-osint -u johndoe
```

From source:

```bash
git clone https://github.com/thalha-a9/helix.git
cd helix
pip install -r requirements.txt
python helix.py -u johndoe
```

The command is installed as both `helix-osint` and `helix`. Use `helix-osint`
where the Helix text editor is also installed (it owns `helix` on Arch Linux).

---

## Installation

**Required**
```bash
pip install aiohttp
```

**Optional extras**
```bash
pip install curl-cffi        # WAF bypass for Twitter, Instagram, TikTok, Patreon
pip install imagehash Pillow # Perceptual avatar hash matching (--phash)
pip install holehe            # Deep email scanning 120+ platforms (--holehe)
                              #   Kali/Debian: if the build fails with "install_layout",
                              #   use: pip install --use-pep517 holehe
pip install "httpx[socks]"    # holehe over --tor / SOCKS proxies
pip install weasyprint        # PDF output for --report
pip install anthropic         # Claude AI verification (--ai claude)
pip install openai            # OpenRouter / NVIDIA AI verification (--ai openrouter)
```

**Or install everything at once**
```bash
pip install "helix-osint[full]"
```

**Set GITHUB_TOKEN for 5000 req/hr on GitHub API** (optional, default is 60/hr):
```bash
export GITHUB_TOKEN=ghp_yourtoken
```

---

## Usage

```bash
# Basic scan: opens interactive graph automatically
python helix.py -u johndoe

# Full power: all intelligence modules
python helix.py -u johndoe --wayback --crt --paste --pivot --phash

# Username + email: two root nodes, cross-matched in graph
python helix.py -u johndoe -e johndoe@gmail.com --breach --holehe

# Dark-web leads + breach sweep, analysed by an LLM with cited sources only
export HIBP_API_KEY=...        # optional: adds Have I Been Pwned to the breach sweep
python helix.py -u johndoe -e johndoe@gmail.com --darkweb --ai claude

# Bigger scan: ~1,080 platforms
python helix.py -u johndoe --wmn --sherlock

# AI-verified scan (free, no API key cost)
python helix.py -u johndoe --ai openrouter

# Recursive pivot: auto-scan aliases up to 4 hops deep
python helix.py -u johndoe --pivot --pivot-depth 4

# Permutations: scan johndoe1, john.doe, realjohndoe, etc.
python helix.py -u johndoe --permutations

# Full database (8,000+ sites), with sealed evidence of the run
python helix.py -u johndoe --all --record-attempt --no-browser
python helix.py --verify-evidence results/johndoe/johndoe_evidence.json results/johndoe/johndoe_sites.json

# Everything, saved to custom dir, no browser
python helix.py -u johndoe -e johndoe@gmail.com \
  --wmn --sherlock --wayback --crt --paste \
  --pivot --phash --breach --holehe \
  --ai openrouter --format all --no-browser --output ~/Desktop/report

# Check which AI providers are configured
python helix.py --providers
```

---

## Operational Security

> **By default every probe leaves from your real IP.** A scan opens dozens of
> near-simultaneous connections to the same username across many platforms:
> a distinctive, easily-logged pattern. A subject who monitors their own
> profile access logs, or who runs a honeypot account on a self-hosted
> instance, can see and attribute the reconnaissance directly to you.
> Route your traffic before scanning anyone real.

```bash
# Route every probe over a local Tor SOCKS port
python helix.py -u johndoe --tor

# Any HTTP/HTTPS/SOCKS4/SOCKS5 proxy
python helix.py -u johndoe --proxy socks5://127.0.0.1:1080
python helix.py -u johndoe --proxy http://user:pass@10.0.0.5:3128

# HTTP_PROXY / HTTPS_PROXY environment variables are honoured as a fallback
HTTPS_PROXY=http://10.0.0.5:3128 python helix.py -u johndoe
```

SOCKS proxies need `aiohttp-socks`:

```bash
pip install aiohttp-socks
```

The proxy covers the whole engine: the username checker, the email checker,
avatar hashing, every intelligence module, and the Sherlock / WhatsMyName /
Maigret / holehe adapters. Helix prints its egress on every run, and warns
when traffic is going out direct. Proxy credentials are redacted from all
output and never written to a report.

### Known subject location

When you already know where the subject is, pass it. Candidate profiles that
*state* a conflicting location are flagged loudly before you confirm them:
the single most common source of mistaken-identity findings.

```bash
python helix.py -u johndoe --location "Wellington, New Zealand"
```

Location is optional and never required. A profile with no stated location is
never penalised, and a conflicting profile is flagged rather than discarded:
the judgement stays yours.

---

## AI Verification

Helix has a two-layer false-positive filter:

**Layer 1: Local heuristic verifier** (always on, zero cost)
Scores every result across 8 signals. A single generic title (e.g. `"Pinterest"` instead of a username) instantly purges the result. WAF/Cloudflare pages scored separately at 80 points. Threshold: 60 for normal results, 85 for OG-validated high-confidence results.

**Layer 2: AI verifier** (`--ai`, optional)
Sends uncertain results to an LLM with a strict system prompt. Three providers:

| Provider | Flag | Cost | Setup |
|---|---|---|---|
| Claude Sonnet 5.5 | `--ai claude` | Paid | `export ANTHROPIC_API_KEY=...` |
| Nemotron 3.5 Super on OpenRouter | `--ai openrouter` | **Free tier** | `export OPENROUTER_API_KEY=...`, key from [openrouter.ai](https://openrouter.ai) |
| Nemotron 3.5 Super on NVIDIA NIM | `--ai nvidia` | **Free tier** | `export NVIDIA_API_KEY=...`, key from [build.nvidia.com](https://build.nvidia.com) |

Every result the AI sees has already passed the control probe, so it may only
remove pages whose title is a login wall, an error or a bot check; it never
overrules the probe on a generic title. If a model is busy, retired or gives
no usable answer, Helix tries the provider's next model, and
`export HELIX_AI_MODEL=<model id>` picks one yourself.

---

## Architecture

```
helix/
|-- helix.py                         # CLI entry point + orchestrator
|-- pyproject.toml                   # pip installable (helix-osint)
|-- osint/
|   |-- checker.py                   # Async engine (aiohttp + optional curl_cffi)
|   |-- platforms.py                 # 56 platform definitions with OG/API detection
|   |-- verifier.py                  # Local heuristic false-positive engine
|   |-- graph.py                     # D3.js relational graph generator
|   |-- report.py                    # JSON / CSV / TXT exporters
|   |-- permutations.py              # Username variation generator
|   |-- pivot.py                     # Concurrent BFS alias pivot engine
|   |-- phash.py                     # Perceptual avatar hash matcher
|   |-- relationships.py             # Declared-only relationship map
|   |-- subject.py                   # Approved-subject identifier gate
|   `-- modules/
|       |-- wayback.py               # Archive.org CDX API + archived HTML parser
|       |-- github_deep.py           # GitHub API deep recon + timezone inference
|       |-- crt.py                   # Certificate transparency (crt.sh)
|       |-- paste.py                 # GitHub Gist intelligence
|       `-- robin.py                 # Dark-web leads (Ahmia) + cited AI analysis
|   `-- adapters/
|       |-- sherlock_adapter.py      # Sherlock data.json loader (24h cached)
|       |-- wmn_adapter.py           # WhatsMyName loader
|       |-- holehe_adapter.py        # holehe email scanner wrapper
|       |-- breachdb.py              # Breach sweep (XposedOrNot, Have I Been Pwned)
|       `-- ai_verifier.py           # Multi-provider async AI verification
|-- bench/                           # Reproducible benchmarks: mock web, precision/recall, records
`-- results/                         # Output (git-ignored)
    `-- username/
        |-- username_graph.html      # Interactive D3.js network graph
        |-- username_TIMESTAMP.json  # Full structured report
        |-- username_TIMESTAMP.csv
        `-- username_TIMESTAMP.txt
```

---

## How False Positive Prevention Works

**Every hit must survive a live cross-check before it is reported.** At the moment of checking, Helix re-requests the profile and two usernames that cannot exist. A hit is kept only if the profile is found again (twice) and both made-up names get the same clear "no such user" answer. A site that "finds" a made-up name is a catch-all, and is dropped. A made-up name that only gets a rate limit, challenge or gateway error proves nothing, so that hit is dropped as unverifiable. Pages judged by status code or by the absence of a not-found message must also name the exact user, so a rate-limit page, a sign-in redirect or a search result listing `jackie` cannot pass for `jack`.

Measured live (Oct 2026) on the `--all` database as it was then (6,158 sites; 8,305 in 3.5.0, see the rehearsals under Benchmarks), default settings:

- **0 false positives** in each of 12 scans of fresh made-up usernames since these checks were added (the last 5 on the current code; 8 per scan before them).
- **Precision on real names:** every sampled hit was a real account when checked against the live page (40 of 40, `--all`, username `jack`; every built-in hit for `jack`, `torvalds`, `max`, `Gargron`).
- **Cross-links:** all cross-links found on 16 real usernames were genuine: Keybase cryptographic proofs and profile links set by the account holder.
- **Avatar matches:** all 5 matches on the same 16 usernames were the identical personal photo, checked by eye; no defaults or look-alikes.
- **Email:** made-up addresses (`@example.com`) get 0 accounts from Gravatar and from holehe's 118 sites.

What "no false positive" means here: a reported account exists. Whether it belongs to *your* subject is a separate question, and that is what the identity grade below answers, and a username match alone is only ever LOW.


Helix uses the right detection method per platform instead of naive HTTP 200 checks:

| Platform | Method | Why |
|---|---|---|
| Reddit | `reddit.com/user/{u}/about.json`, the `"is_employee"` field | JSON API; field only exists for valid users |
| Bluesky | AT Protocol API | SPA: static HTML is useless |
| Chess.com | `api.chess.com/pub/player/{u}` | Official public API |
| Lichess | `lichess.org/api/user/{u}` | Official public API |
| GitHub | `og:title` parsed + validated against known error strings | Server-side rendered, reliable |
| Medium | `og:title` rejects homepage redirect string | Catches "Where good ideas find you" |
| Twitter/X | not-found text + the page must name the user (`curl_cffi`) | Skipped gracefully without curl_cffi |
| Instagram | profile `og:title` "Name (@user)" | Logged out, anything else is a wall |
| TikTok | embedded user record `"uniqueId":"user"` | Unknown names get statusCode 10221 |
| Keybase | public lookup API | Pages lost og:title; the API also gives cryptographic proofs |
| Facebook, Threads | never reported | Logged out they show the same wall for every name |

---

## Control Probe

Measured live on 29 Oct 2026, the full database at the time (8,381 sites), a username
nobody has: **72 accounts "found" with the control probe off, 0 with it on.**

Big username databases are full of sites that answer "found" for **any** name:
login walls (Facebook and Instagram when logged out), catch-all pages, sites
whose markup changed since the database entry was written. A single site like
that puts a fake account in every report.

So every hit is re-checked, at the same moment, against two random usernames
that cannot exist. The hit survives only if it is found again (twice) and both
random names get the same clear "no such user" answer. A site that "finds" a
random name is a catch-all; a random name that only gets a rate limit,
challenge or gateway error proves nothing, so that hit is dropped as
unverifiable. No per-site tuning: it holds across the whole database. Sites seen
answering unknown names at random are blocked outright.

Leads from the Maigret engine get the same treatment by URL: the page must name
the user, two random names must both get the same clear answer, and a lead
whose URL cannot be rebuilt for another name is not kept. `--no-control` turns
the probe off (faster, **not** covered by the no-false-positive measurements).

Database entries are also validated before they are scanned: a URL that is not
a real web address, an unfilled template, or a detection rule with no evidence
(which would match every page) is skipped and counted.

---

## Identity Confidence

Finding an account proves the account exists. It does not prove it belongs to
your subject. Every finding gets a separate identity grade built only from
independent evidence that agrees:

| Selector | Evidence |
|---|---|
| username | same username: every finding has this, so on its own it is weak |
| avatar | perceptual-hash match with another found profile (`--phash`) |
| cross_link | the profile's bio links to another found profile, or vice versa |
| email | the same platform was also confirmed from the subject's email (`-e ... --holehe`) |
| real_name | the page names the real name extracted from a *different* profile |
| location | the stated location agrees with `--location` |

- **LOW**: username only. Treat as a lead, not a finding.
- **MEDIUM**: two selectors.
- **HIGH**: three selectors, or two where one is avatar, cross-link or email.

A single selector is never HIGH, status-code-only detection caps at MEDIUM, and
a location conflict caps at LOW. The supporting evidence is listed next to
every grade in the console and in all reports.

---

## Output Formats

| Format | Contents |
|---|---|
| `.html` | Standalone interactive D3.js graph: no server needed |
| `_report.html` / `.pdf` | Investigation report (`--report`; PDF needs weasyprint) |
| `.json` | Full structured report including intel bundle (wayback, GitHub deep, CRT, paste) |
| `.csv` | Spreadsheet-friendly, all platforms |
| `.txt` | Clean terminal-style summary |

---

## Benchmarks

Every number Helix publishes comes from `bench/` and can be re-run by anyone:

```bash
python -m bench.benchmark --sites 6000 --concurrency 300 --repeat 3 --json bench/results/my_run.json
```

The harness serves 6,000 fake platforms from a separate process, 2 % of them
catch-alls that answer "found" for any name, and scores the full pipeline
(scan, control probe, then verifier) against exact ground truth.

| 29 Oct 2026, 6,000 sites, control probe on | sites/s | precision | recall | false positives |
|---|---|---|---|---|
| default concurrency (60) | 260.9 | 1.000 | 1.000 | 0 |
| `--concurrency 300` | 387.0 | 1.000 | 1.000 | 0 |

**Live, sealed record rehearsal** (29 Oct 2026, final 3.5.0 code, `--all --record-attempt --save-pages --concurrency 250`):

| username | sites | clear answers | accounts reported | wall |
|---|---|---|---|---|
| made up at random just before the run | 8,305 | 6,918 | **0** | 167.1 s |
| `jack` (789 pages saved and hashed) | 8,305 | 6,791 | 789 | 265.8 s |

The made-up-name evidence is published in `bench/results/` and verifies with
`helix-osint --verify-evidence`.

That run was on a fast data-centre link. The same check on a laptop over a
mobile hotspot (30 Oct 2026, Kali, 4 threads), 8,305 sites each time:

| `--concurrency` | clear answers | accounts reported (made-up name) | wall |
|---|---|---|---|
| 100 | 6,971 | **0** | 516.7 s |
| **150** | **7,032** | **0** | **419.6 s** |
| 250 | 7,022 | **0** | 445.8 s |

So expect a few minutes for `--all` on a fast connection and 7 to 9 minutes on
a slow one. The best `--concurrency` depends on the link: 250 was fastest on
the data-centre link, but on the hotspot it overloaded the connection (about
2,350 probes timed out on the first pass, against 580 at 150) and the re-check
pass made it slower. Start at 150 and compare the clear-answer count.

Metric definitions, the record files and the live method are in [`bench/README.md`](bench/README.md).

---

## Contributing

Pull requests are welcome. For major changes open an issue first.

When adding a platform to `platforms.py`:
- Prefer `og_meta` or API endpoints over `text_not_present`
- Always test against a non-existent username first: if it returns `found=True`, your detection is wrong
- Add `bio_extract: True` + `bio_patterns` if the platform renders bio text server-side

---

## Legal & Ethics

Helix is built for **security research, bug bounty reconnaissance, and OSINT education**.
All data sources used are publicly accessible. Always ensure you have proper authorization
before running reconnaissance on any target. The author is not responsible for misuse.

---

## Related Projects

- [esp32-iot-audit](https://github.com/thalha-a9/esp32-iot-audit): ESP32 IoT security scanner
- [esp-pentest-toolkit](https://github.com/thalha-a9/esp-pentest-toolkit): Wireless ESP32/8266 pentest toolkit

---

<div align="center">

Built by **Thalha Ahmed** | [@thalha-a9](https://github.com/thalha-a9)

*If Helix helped you: drop a star and share it with your security community.*

</div>
