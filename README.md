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
[![Version](https://img.shields.io/badge/Version-3.1.0-00ff88?style=flat-square)](https://github.com/thalha-a9/helix/releases)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=flat-square)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-70%2B%20builtin%20·%20700%2B%20WMN%20·%20400%2B%20Sherlock%20·%20Maigret-a78bfa?style=flat-square)](https://github.com/thalha-a9/helix)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/thalha-a9/helix/pulls)

**Helix** is a next-generation open-source OSINT framework that goes far beyond username checking.<br>
It maps the *actual connections* between a target's online identities — then renders them as a<br>
live, interactive D3.js relational graph you can explore, filter, and export.

[**Quick Start**](#-quick-start) · [**Features**](#-what-makes-helix-different) · [**Modules**](#-intelligence-modules) · [**Graph**](#-the-graph) · [**Install**](#-installation)

</div>

---

## Why Helix?

Most OSINT tools answer one question: *"Does this username exist on Platform X?"*

Helix answers a harder one: **"How do all these accounts connect to the same person?"**

It extracts cross-platform links from bios, matches profile pictures by perceptual hash, infers timezone from commit patterns, discovers domains via certificate transparency, and plots every relationship as a glowing edge in a browser-based network graph — all in a single command.

```bash
python helix.py -u johndoe --wayback --crt --paste --pivot --phash
```

---

## ⚡ What Makes Helix Different

| Capability | Sherlock | SpiderFoot | Maltego | **Helix** |
|---|:---:|:---:|:---:|:---:|
| Username enumeration | ✓ | ✓ | ✓ | ✓ |
| Relational bio-link graph | ✗ | ✗ | Partial | **✓** |
| Recursive alias pivot | ✗ | ✗ | Manual | **✓ auto** |
| Perceptual avatar matching | ✗ | ✗ | ✗ | **✓** |
| Timezone inference | ✗ | ✗ | ✗ | **✓** |
| Wayback identity timeline | ✗ | Partial | ✗ | **✓** |
| Certificate transparency | ✗ | ✓ | ✓ | **✓** |
| GitHub commit email extraction | ✗ | ✗ | ✗ | **✓** |
| Local heuristic verifier | ✗ | ✗ | ✗ | **✓ always-on** |
| Multi-AI false-positive filter | ✗ | ✗ | ✗ | **✓ 3 providers** |
| Async speed | ✗ | ✗ | ✗ | **✓** |
| 100% free & open source | ✓ | ✓ | ✗ | **✓** |

---

## 🔍 Intelligence Modules

### Always On
- **Local Heuristic Verifier** — Zero-dependency false-positive engine. Scores every result across 8 signals (WAF pages, generic titles, login redirects, homepage redirects). Runs before anything else, every single scan.

### Core Flags
| Flag | What it does |
|---|---|
| `--wmn` | Loads WhatsMyName database at runtime — **700+ platforms**, community-maintained |
| `--maigret` | Loads **Maigret** database at runtime — sophisticated detection with `presenceStrs`/`absenceStrs`, 24h cached |
| `--sherlock` | Loads Sherlock's database at runtime — **400+ platforms**, cached 24h locally |
| `--pivot` | **Recursive bio pivot** — finds aliases in bios and auto-scans them, up to 4 hops deep |
| `--phash` | **Perceptual avatar hash** — downloads profile pics, hashes them, cross-matches across platforms. Finds the same person even if they changed their username |
| `--wayback` | **Wayback Machine** — fetches snapshot history + parses archived HTML for old usernames, historic emails, and past bios |
| `--crt` | **Certificate Transparency** — queries crt.sh for SSL certs containing the target's name or email. Finds personal domains that never appeared in any bio |
| `--paste` | **Paste Intelligence** — searches GitHub Gists and public Pastebin index for mentions |
| `--breach` | **Breach check** — queries XposedOrNot for breach metadata (names, dates, data types exposed). No credentials returned |
| `--holehe` | **Deep email scan** — hands off to holehe for 120+ platform email-registration checks |
| `--ai` | **AI false-positive filter** — second verification pass via Claude, OpenRouter (free), or NVIDIA NIM (free) |

### Auto-Triggered
- **GitHub Deep Recon** — runs automatically when a GitHub profile is found. Extracts real emails from public commits (filters noreply), org memberships, language stats, npm packages, and infers timezone from commit timestamp distribution (requires ≥15 commits for confidence)

---

## 🕸 The Graph

The HTML output is a standalone zero-dependency interactive network — no server needed, just open in a browser.

```
White pulsing node     →  Username root
Amber pulsing node     →  Email root
Amber/orange nodes     →  Pivot-discovered aliases
Green solid edges      →  Bio-extracted cross-links (proven connections)
Pink dashed edges      →  Avatar hash matches (same person across accounts)
Amber dashed edges     →  Email-matched platforms
Green ring on node     →  High confidence (OG meta validated)
Blue ring on node      →  Medium confidence
```

**Controls:** drag nodes · scroll to zoom · click node to open profile · hover for tooltip (confidence, og:title, cross-link partners, bio-extracted alias details) · ⌕ search · ◌ not-found overlay · ☰ labels · ↓ SVG export · filter by confidence

---

## 🚀 Quick Start

```bash
git clone https://github.com/thalha-a9/helix.git
cd helix
pip install -r requirements.txt
python helix.py -u johndoe
```

---

## 📦 Installation

**Required**
```bash
pip install aiohttp
```

**Optional — unlock more power**
```bash
pip install curl-cffi        # WAF bypass for Twitter, Instagram, TikTok, Patreon
pip install imagehash Pillow # Perceptual avatar hash matching (--phash)
pip install holehe            # Deep email scanning 120+ platforms (--holehe)
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

## 💻 Usage

```bash
# Basic scan — opens interactive graph automatically
python helix.py -u johndoe

# Full power — all intelligence modules
python helix.py -u johndoe --wayback --crt --paste --pivot --phash

# Username + email — two root nodes, cross-matched in graph
python helix.py -u johndoe -e johndoe@gmail.com --breach --holehe

# Massive scan — 1100+ platforms
python helix.py -u johndoe --wmn --sherlock

# AI-verified scan (free — no API key cost)
python helix.py -u johndoe --ai openrouter

# Recursive pivot — auto-scan aliases up to 4 hops deep
python helix.py -u johndoe --pivot --pivot-depth 4

# Permutations — scan johndoe1, john.doe, realjohndoe, etc.
python helix.py -u johndoe --permutations

# Everything, saved to custom dir, no browser
python helix.py -u johndoe -e johndoe@gmail.com \
  --wmn --sherlock --wayback --crt --paste \
  --pivot --phash --breach --holehe \
  --ai openrouter --format all --no-browser --output ~/Desktop/report

# Check which AI providers are configured
python helix.py --providers
```

---

## 🕶 Operational Security

> **By default every probe leaves from your real IP.** A scan opens dozens of
> near-simultaneous connections to the same username across many platforms —
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

The proxy covers the whole engine — the username checker, the email checker,
avatar hashing, every intelligence module, and the Sherlock / WhatsMyName /
Maigret / holehe adapters. Helix prints its egress on every run, and warns
when traffic is going out direct. Proxy credentials are redacted from all
output and never written to a report.

### Known subject location

When you already know where the subject is, pass it. Candidate profiles that
*state* a conflicting location are flagged loudly before you confirm them —
the single most common source of mistaken-identity findings.

```bash
python helix.py -u johndoe --location "Wellington, New Zealand"
```

Location is optional and never required. A profile with no stated location is
never penalised, and a conflicting profile is flagged rather than discarded —
the judgement stays yours.

---

## 🤖 AI Verification

Helix has a two-layer false-positive filter:

**Layer 1 — Local heuristic verifier** (always on, zero cost)
Scores every result across 8 signals. A single generic title (e.g. `"Pinterest"` instead of a username) instantly purges the result. WAF/Cloudflare pages scored separately at 80 points. Threshold: 60 for normal results, 85 for OG-validated high-confidence results.

**Layer 2 — AI verifier** (`--ai`, optional)
Sends uncertain results to an LLM with a strict system prompt. Three providers:

| Provider | Flag | Cost | Setup |
|---|---|---|---|
| Anthropic Claude | `--ai claude` | Paid | `export ANTHROPIC_API_KEY=...` |
| OpenRouter Llama 3.1 | `--ai openrouter` | **Free tier** | `export OPENROUTER_API_KEY=...` → [openrouter.ai](https://openrouter.ai) |
| NVIDIA NIM Llama 3.1 | `--ai nvidia` | **Free tier** | `export NVIDIA_API_KEY=...` → [build.nvidia.com](https://build.nvidia.com) |

---

## 🏗 Architecture

```
helix/
├── helix.py                         ← CLI entry point + orchestrator
├── pyproject.toml                   ← pip installable (helix-osint)
├── osint/
│   ├── checker.py                   ← Async engine (aiohttp + optional curl_cffi)
│   ├── platforms.py                 ← 70+ platform definitions with OG/API detection
│   ├── verifier.py                  ← Local heuristic false-positive engine
│   ├── graph.py                     ← D3.js relational graph generator
│   ├── report.py                    ← JSON / CSV / TXT exporters
│   ├── permutations.py              ← Username variation generator
│   ├── pivot.py                     ← Concurrent BFS alias pivot engine
│   ├── phash.py                     ← Perceptual avatar hash matcher
│   └── modules/
│       ├── wayback.py               ← Archive.org CDX API + archived HTML parser
│       ├── github_deep.py           ← GitHub API deep recon + timezone inference
│       ├── crt.py                   ← Certificate transparency (crt.sh)
│       └── paste.py                 ← Gist + Pastebin intelligence
│   └── adapters/
│       ├── sherlock_adapter.py      ← Sherlock data.json loader (24h cached)
│       ├── wmn_adapter.py           ← WhatsMyName loader
│       ├── holehe_adapter.py        ← holehe email scanner wrapper
│       ├── breach_adapter.py        ← XposedOrNot breach metadata
│       └── ai_verifier.py           ← Multi-provider async AI verification
└── results/                         ← Output (git-ignored)
    └── username/
        ├── username_graph.html      ← Interactive D3.js network graph
        ├── username_TIMESTAMP.json  ← Full structured report
        ├── username_TIMESTAMP.csv
        └── username_TIMESTAMP.txt
```

---

## 🔬 How False Positive Prevention Works

Helix uses the right detection method per platform instead of naive HTTP 200 checks:

| Platform | Method | Why |
|---|---|---|
| Reddit | `reddit.com/user/{u}/about.json` → `"is_employee"` field | JSON API; field only exists for valid users |
| Bluesky | AT Protocol API | SPA — static HTML is useless |
| Chess.com | `api.chess.com/pub/player/{u}` | Official public API |
| Lichess | `lichess.org/api/user/{u}` | Official public API |
| GitHub | `og:title` parsed + validated against known error strings | Server-side rendered, reliable |
| Medium | `og:title` rejects homepage redirect string | Catches "Where good ideas find you" |
| Twitter/X | `curl_cffi` TLS impersonation | Skipped gracefully without it |

---

## 📋 Output Formats

| Format | Contents |
|---|---|
| `.html` | Standalone interactive D3.js graph — no server needed |
| `.json` | Full structured report including intel bundle (wayback, GitHub deep, CRT, paste) |
| `.csv` | Spreadsheet-friendly, all platforms |
| `.txt` | Clean terminal-style summary |

---

## 🤝 Contributing

Pull requests are welcome. For major changes open an issue first.

When adding a platform to `platforms.py`:
- Prefer `og_meta` or API endpoints over `text_not_present`
- Always test against a non-existent username first — if it returns `found=True`, your detection is wrong
- Add `bio_extract: True` + `bio_patterns` if the platform renders bio text server-side

---

## ⚠️ Legal & Ethics

Helix is built for **security research, bug bounty reconnaissance, and OSINT education**.
All data sources used are publicly accessible. Always ensure you have proper authorization
before running reconnaissance on any target. The author is not responsible for misuse.

---

## 📎 Related Projects

- [esp32-iot-audit](https://github.com/thalha-a9/esp32-iot-audit) — ESP32 IoT security scanner
- [esp-pentest-toolkit](https://github.com/thalha-a9/esp-pentest-toolkit) — Wireless ESP32/8266 pentest toolkit

---

<div align="center">

Built by **Thalha Ahmed** · [@thalha-a9](https://github.com/thalha-a9)

*If Helix helped you — drop a ⭐ and share it with your security community.*

</div>
