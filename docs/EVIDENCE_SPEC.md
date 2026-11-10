# Helix evidence specification

Version 1. This document defines the files Helix writes when a scan is run as
evidence, how each is hashed, how to check them, and how they relate to the
Berkeley Protocol on Digital Open Source Investigations (OHCHR and the Human
Rights Center, UC Berkeley School of Law).

There are three kinds of file:

| Flag | Files | Schema |
|---|---|---|
| `--record-attempt` | `<label>_evidence.json`, `<label>_sites.json` | `helix.record-attempt.v1` |
| `--save-pages` | `<label>_pages/manifest.json`, one `.txt` file per page, `index.html` | `helix.pages.v1` |
| `--watch` | `<label>_watch/history.jsonl`, `<label>_watch/sites_<hash>.json` | `helix.watch.v1` |

## 1. Common rules

- **Hash.** SHA-256, written as 64 lower-case hexadecimal characters.
- **Canonical JSON.** Where a hash covers JSON data, the data is serialised
  with keys sorted, `,` and `:` as separators with no spaces, non-ASCII
  characters written as themselves, and encoded as UTF-8. The same data gives
  the same bytes on any machine.
- **Time.** UTC, ISO 8601, from the clock of the machine that ran the scan.
- **Counting.** A site is *answered* when it gave a clear answer: an account
  found, or a definite "not found". A "not found" that came with HTTP 401,
  403, 407, 408, 425, 429, 451, 999 or 5xx is not a clear answer. A site that
  gave no clear answer is counted under the reason and is never counted as
  "no account".

## 2. The scan record (`--record-attempt`)

`<label>_evidence.json` is one JSON object:

| Field | Content |
|---|---|
| `schema` | `helix.record-attempt.v1` |
| `tool` | `name`, `version`, `commit` (the git commit when run from a checkout), `homepage` |
| `attempt.username` | the username, or the address when `attempt.target_type` is `email` |
| `attempt.started_utc`, `finished_utc`, `wall_seconds` | when the scan ran |
| `attempt.command` | the command line, with any proxy password removed |
| `attempt.concurrency` | requests in flight at once |
| `attempt.control_probe`, `attempt.controls` | whether every hit was re-checked, and against how many made-up names |
| `attempt.purpose` | why the scan was run, from `--purpose`, or `not stated` |
| `attempt.collector` | who ran it, from `--collector` (left out when not given) |
| `environment` | Python version, operating system, machine, CPU count, and how requests left the machine (direct, or which proxy, without credentials) |
| `database.sites`, `database.sha256`, `database.file` | how many sites were scanned, the SHA-256 of the canonical site definitions, and the file that holds them |
| `database.switched_off` | when sites were left out by the daily site check: how many, and the date of the list |
| `counting_rules` | the counting rules above, in words, so the file explains itself |
| `pages` | when `--save-pages` was used: the folder, the number of pages and the SHA-256 of the manifest |
| `summary` | `attempted`, `answered`, `found`, `not_found`, `unanswered`, `unanswered_by_reason`, `retried_after_timeout`, `second_attempt` (by `retry`, `fallback`, `tls`), `sources` |
| `found` | each reported account: `platform`, `url`, `source` |
| `per_site` | every site: `platform`, `source`, `url`, `found`, `status`, `error`, and `page_sha256` where a page was saved |
| `fingerprint` | SHA-256 of the canonical JSON of every other field |

`<label>_sites.json` is the canonical JSON of the exact site definitions
scanned. Its SHA-256 is `database.sha256`.

The fingerprint is printed at the end of the run. Recorded on screen or read
out to a witness, it ties that moment to this one file: change one byte and
it no longer matches.

**Check:** `helix --verify-evidence <label>_evidence.json <label>_sites.json`
recomputes the fingerprint, the site list hash, the sums
(`answered + unanswered = attempted`, `found` equals the length of the found
list) and, when the pages folder is next to the record, every page hash.

## 3. Saved pages (`--save-pages`)

For every reported account Helix keeps the response that made it report the
account:

- `NNN_<site>.txt`: the raw response body, the bytes exactly as received, up
  to 512 KB. The `.txt` extension makes a browser show it as text, so a saved
  page cannot run its scripts.
- `manifest.json`: for each page the site, the address requested, the address
  the response came from after redirects, the HTTP status, the response
  headers (cookies and authorisation headers are dropped), the UTC time of
  arrival to the millisecond, whether the body was cut at the size limit, and
  the SHA-256 of the body.
- `index.html`: the manifest as a table for people.

The SHA-256 of `manifest.json` is sealed into the scan record
(`pages.manifest_sha256`), and each page hash appears in `per_site`.

**Check:** `helix --verify-pages <label>_pages` re-hashes every page against
the manifest.

## 4. Watch history (`--watch`)

`history.jsonl` holds one snapshot per line. A snapshot records the username,
the time, the purpose, how many sites were scanned and answered, the hash of
the site list, the accounts found (each with the public facts compared
between snapshots), and the sites that gave no clear answer.

Each snapshot carries `prev`, the hash of the snapshot before it (empty for
the first), and `hash`, the SHA-256 of its own canonical JSON without the
`hash` field. Changing, removing, adding or reordering a snapshot breaks
every hash after it. Helix refuses to add to a history that fails this check.

`sites_<hash>.json` is the list of site keys a snapshot was taken on, written
once per distinct list, so "new" and "removed" are only claimed for sites
that were scanned and answered both times.

**Check:** `helix --verify-watch <label>_watch`.

## 5. How this relates to the Berkeley Protocol

The Protocol sets out principles and a process for open source
investigations whose results may be used in court. The table gives the
author's reading of what the Protocol asks at each step and what Helix
records for it. It is not a certification, and the Protocol's authors have
not reviewed it.

| The Protocol asks for | What Helix records | Not covered by Helix |
|---|---|---|
| **Accountability and transparency of method:** the process can be explained and repeated | Tool version and commit, the exact command, the site definitions with their hash, the counting rules in the file itself | |
| **Legality and a defined purpose** | `attempt.purpose` and `attempt.collector`, sealed under the fingerprint | Whether the purpose is lawful: that is the investigator's assessment (see RESPONSIBLE_USE.md) |
| **Accuracy** | Every reported account was re-fetched and the site refused at least three made-up names; unanswered sites are counted by reason, never as "no account"; identity grades separate "same name" from "same person" | |
| **Data minimisation** | Only sites are queried, only reported accounts have pages saved, optional modules are off unless asked for, adult sites are off by default | What the investigator keeps afterwards |
| **Security awareness** | The record states how requests left the machine (direct or by proxy); `--tor` and `--proxy` route every request | Operational security beyond the network route |
| **Collection: the web address** | Address requested and final address after redirects, per page | |
| **Collection: the source code** | The raw response body, unchanged | Content a browser would load afterwards with scripts |
| **Collection: a full-page capture** | | Helix takes no screenshot. Capture one separately where the visual appearance matters |
| **Collection: embedded media and metadata** | Response headers | Images and video on the page are not downloaded (the profile picture is hashed with `--phash`, not kept) |
| **Collection: who collected, from where, when** | `attempt.collector`, UTC times per page and per scan, the egress description | The collector's IP address is not recorded. The clock is the machine's own, not a trusted timestamp |
| **Collection: a hash value** | SHA-256 of every page, of the manifest, of the site list and of the whole record | |
| **Preservation: authenticity and integrity over time** | The fingerprint and the hash chain make later changes detectable | Storage, back-ups and the split between an evidentiary copy and a working copy are the investigator's to arrange |
| **Preservation: chain of custody** | The record fixes what was collected and when; `--verify-evidence` lets each later holder show it is unchanged | The log of who held the files after collection |
| **Verification of source and content** | The control probe, the identity grades with their evidence, location conflicts, the declared-relationship map | Judging whether an account is authentic or impersonated: Helix gives signals, the investigator decides |
| **Reporting: findings with their limits** | The HTML and PDF report state how many sites did not answer and why, and mark leads as leads | |

### Using Helix under the Protocol

A scan meant as evidence should be run as:

```bash
helix -u NAME --all --record-attempt --save-pages \
      --purpose "why this scan is run" --collector "who runs it"
```

Then:

1. Note the fingerprint somewhere outside the machine (a case log, a
   witnessed recording).
2. Copy the output folder to write-once storage as the evidentiary copy and
   work on a second copy.
3. Capture screenshots of the accounts that matter with a separate tool, and
   hash them.
4. Log each hand-over of the files, and have each holder run
   `--verify-evidence`.
