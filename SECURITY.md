# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 3.5.x | Yes |
| older | No, please upgrade: `pipx upgrade helix-osint` |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
https://github.com/thalha-a9/helix/security/advisories/new

Don't open a public issue for them. Include what is affected, how to reproduce
it, and what an attacker could do. You'll get a reply within 7 days, and a
fix for a confirmed issue is released as soon as it's ready, with credit to
you in the changelog unless you'd rather not be named.

## What counts

Helix fetches pages from sites it doesn't control, so these are in scope:

* a fetched page or API response that can make Helix reach internal network
  addresses, write outside the output folder, or run code;
* output that can inject into the terminal, the HTML or PDF report, the
  graph, or CSV files opened in a spreadsheet;
* traffic that leaves outside the proxy when `--proxy` or `--tor` is set;
* a way to change a `--record-attempt` evidence file or a saved page without
  `--verify-evidence` or `--verify-pages` noticing.

Out of scope: how third-party sites behave, and results that are wrong but
not a security problem (please use the issue forms for those).
