# Helix benchmarks

Numbers about Helix are only worth something if anyone can reproduce them.
This directory holds the harness that produces every performance and accuracy
figure Helix publishes, and the records it produced.

## The metrics

Every metric is measured on **one full scan** (`check_username` with the
control probe, then the local heuristic verifier), end to end, wall clock.

| Metric | Definition |
|---|---|
| **sites/s** | platforms checked / wall-clock seconds, including the control probe and verifier |
| **precision** | accounts reported that truly exist / accounts reported |
| **recall** | accounts reported that truly exist / accounts that truly exist |
| **false positives** | accounts reported that do not exist (the number Helix is built to keep at 0) |

Two benchmarks, same metrics:

### 1. Mock web (offline, exact ground truth)

`bench/mockweb.py` serves N fake platforms from a separate process, so the
server's CPU never counts against the engine. A seeded RNG makes each site
*normal* (a profile only for the users it has), a *catch-all* (200 for any
name: login walls and search pages, the classic false-positive trap) or
*dead* (never answers). A *short* catch-all accepts any name up to 11
characters and refuses longer ones with 400 or 404 (`--short-catchall-frac`,
2 % by default); it is there because made-up names longer than the subject
cannot catch it. The manifest says exactly which sites have the
subject, so precision and recall are exact, not sampled.

```bash
python -m bench.benchmark --sites 6000                     # default concurrency
python -m bench.benchmark --sites 6000 --concurrency 300
python -m bench.benchmark --sites 1000 --dead-frac 0.10    # the dead-host tax
python -m bench.benchmark --sites 1000 --no-control        # what the probe buys
python -m bench.benchmark --sites 6000 --repeat 3 --json bench/results/my_run.json
```

Every run can be written as JSON with the Helix version, git commit, Python
version, host and every parameter, so a figure can be re-run by anyone.

### 2. Live (real platforms, sampled ground truth)

The mock web measures the engine; it cannot measure the platform definitions.
For those, scan made-up usernames (every hit is a false positive by
construction) and real usernames whose hits are checked by hand:

```bash
python helix.py -u xq7v2mzt9plk --all --no-browser      # a name nobody has: expect 0
python helix.py -u torvalds --all --no-browser           # then check every hit live
```

## Records

### Mock web: 29 Oct 2026, Helix 3.4.0 (`6a66c3b`), Python 3.13, 4 CPUs

6,000 sites | 50 ms latency | 2 % catch-alls | control probe on | best of 2

| concurrency | sites/s | wall | precision | recall | false positives |
|---|---|---|---|---|---|
| 60 (default) | 260.9 | 23.0 s | 1.000 | 1.000 (587/587) | 0 |
| 300 (`--concurrency 300`) | 387.0 | 15.5 s | 1.000 | 1.000 (587/587) | 0 |

All 130 catch-all sites were discarded by the control probe in both runs.
Records: `results/2026-10-29_mockweb_6000_default.json`,
`results/2026-10-29_mockweb_6000_c300.json`.

### Live: final sealed record rehearsal, 29 Oct 2026, Helix 3.5.0 (release code)

Full database with adult sites and search pages excluded (the default),
`--all --record-attempt --save-pages --concurrency 250`, timeouts retried at
60, every hit through the control probe with shape-matched impossible names.

| username | sites attempted | clear answers | accounts reported | wall |
|---|---|---|---|---|
| `hxqgni0luz2h`, generated at random just before the run | 8,305 | 6,918 | **0** | 167.1 s |
| `jack` (789 pages saved and hashed, 70 MB) | 8,305 | 6,791 | 789 | 265.8 s |

All 45 `--permutations` variants of another made-up name: 0 accounts.

Evidence: `results/2026-10-29_record_rehearsal_final_madeup/` (compressed),
fingerprint `aecfbf9d6f088f8d1b628e1aaaf32938bcd315de61bd8fffed99ffb8aff728be`.

```bash
helix-osint --verify-evidence \
  bench/results/2026-10-29_record_rehearsal_final_madeup/hxqgni0luz2h_evidence.json.gz \
  bench/results/2026-10-29_record_rehearsal_final_madeup/hxqgni0luz2h_sites.json.gz
```

### Live: first sealed record rehearsal, 29 Oct 2026, earlier 3.5.0 build

Full database (adult sites excluded, the default), `--all --record-attempt
--concurrency 250`, timeouts retried at 60, every hit through the control
probe. Run through this machine's HTTP proxy, which itself refused some hosts.

| username | sites attempted | clear answers | accounts reported | wall |
|---|---|---|---|---|
| `hxahels91dd0`, generated at random just before the run | 8,377 | 6,924 | **0** | 188.6 s |
| `jack` | 8,377 | 6,812 | 791 | 288.6 s |

Why the other sites gave no clear answer, for the made-up name: bot-check
page 501, connection error 224, timeout 204, HTTP 403 147, site "finds"
impossible usernames 125 (the control probe removed them), proxy refused or
other 89. None of them can produce a reported account.

The made-up-name evidence is published:
`results/2026-10-29_record_rehearsal_madeup/` (compressed). Check it:

```bash
helix-osint --verify-evidence \
  bench/results/2026-10-29_record_rehearsal_madeup/hxahels91dd0_evidence.json.gz \
  bench/results/2026-10-29_record_rehearsal_madeup/hxahels91dd0_sites.json.gz
```

Fingerprint `56cd603e89ca995d6208d8cbd268ee2dc6c56e2d237935f4d88b90c17313326c`.

### Live: what the control probe is worth, 29 Oct 2026

The same made-up username, the full database with adult sites included
(8,381 sites), run once with the control probe switched off:

| control probe | accounts reported for a name nobody has |
|---|---|
| off (`--no-control`) | **72**, every one false |
| on (default) | **0** (every full run, sealed rehearsals included) |

The 72 come from sites that answer "found" for any name: login walls,
catch-all pages, changed markup. The local verifier already removed 38
more before those 72 were counted. This is what every scan without a
per-hit check reports.

### Live: concurrency and the retry pass, `jack`, 8,453 sites (adult sites included)

| probes in flight | retry pass | accounts | wall |
|---|---|---|---|
| 60 | no | 807 | 242 s |
| 60 | yes | 809 | 344 s |
| 250 | no | 695 | 158 s |
| 250 | yes | **811** | 292 s |

250 without the retry lost 106 real accounts to timeouts on this link; with
it, 250 was the most complete of the four. About a dozen accounts swap in
and out between any two live runs as sites flicker, so treat differences
under ~15 as noise.

### Live: earlier, 29 Oct 2026, default concurrency, 8,453 sites (adult sites included)

| scan | sites | wall | found | control probe discarded |
|---|---|---|---|---|
| `-u xq7v2mzt9plk --all` (name nobody has) | 8,453 | 181.5 s | **0** | 122 catch-all platforms |
| same, `--concurrency 250`, no retry | 8,453 | 112.2 s | **0** | 102, but 1,423 sites timed out, so not a full check |

## Publishing a number

1. Run the mock-web benchmark with `--repeat 3 --json bench/results/<date>_<what>.json`.
2. Add a row to the tables above, naming the commit and the parameters.
3. Commit the JSON with the row. A number with no record file is not a benchmark.
