# The daily site check

A list of sites rots. Domains expire, forums close, and a redesign breaks the
rule that told an account from an empty page. A scanner that keeps asking
those sites reports "not found" for places where it could never have found
anything.

Helix checks every site it can scan once a day and leaves the broken ones
out by itself. The record is public: <https://thalha-a9.github.io/helix/>.

## What one check does

For every site:

1. It asks for a made-up name. A working site says "no such user".
2. Where a site has a known account (the databases list one for most sites,
   a fediverse server names its own admin, the built-in sites carry one), it
   asks for that account. A working site finds it.

Each site ends up in one state:

| State | Meaning |
|---|---|
| proven | A real account was found and a made-up name was not. |
| answers | A made-up name got a clear "no such user". No test account is listed, or the listed one was not found (accounts get deleted, so that alone does not make the site broken). |
| blocked | The site refused the checker's network: bot check, HTTP 401 or 403, rate limit. It may work from yours. Never switched off for this. |
| dead | The host name does not resolve, the certificate is invalid, the connection fails or times out, or the server answers 5xx. |
| broken | The rule reported an account for a made-up name, so it cannot tell names apart. |
| unknown | Anything else, such as a host the checker itself could not reach. |

## Switching off

A site that is dead or broken on 3 checks in a row is switched off. Checks
less than 20 hours apart count as one, so that means 3 separate days. The
first check that finds the site working switches it back on.

A scan leaves switched-off sites out and says so:

```
[i] 412 site(s) left out: dead or broken on 3 daily checks in a row (list of 2026-11-13). --include-off scans them anyway.
```

A sealed record (`--record-attempt`) states how many sites were left out and
which list was used, under `database.switched_off`. The JSON report lists
each one with the reason.

The check runs from one network (a GitHub Actions runner). "dead" means dead
from there: a site that drops connections from a data centre can still work
from a home line. Pass `--include-off` to scan everything.

## Where the list comes from

- Every release ships the list as it was that day (`osint/data/switched_off.json`).
- The daily job publishes a fresh one on the `status` branch. A scan that
  downloads the site databases also fetches it, at most once a day. If the
  download fails, the list at hand stays in use.

## Running it yourself

```bash
python -m osint.health check --state status/state.json --out status
python -m osint.health page  --state status/state.json --out status
```

`check` takes about 8 minutes for the full list on a fast link and writes
`state.json` (every site and the last 90 checks), `switched_off.json` (the
list scans read) and `index.html` (the status page, one file, no scripts
from elsewhere).

The daily job is `.github/workflows/site-check.yml`.
