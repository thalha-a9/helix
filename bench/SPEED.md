# Speed against other tools

One run each on 10 Nov 2026, same machine (4 CPUs), same cloud data-centre
connection, same hour, each tool's documented full scan of one made-up
username (so no real account exists anywhere and every "found" is wrong).

| Tool | Command | Sites | Seconds | Sites a second | Accounts reported for the made-up name |
|---|---|---|---|---|---|
| Helix (this branch) | `helix -u NAME --all --record-attempt` | 11,302 | 217 | 52 | 0 |
| Maigret 0.6.6 | `maigret NAME -a --no-recursion` | 8,245 | 147 | 56 | 0 |
| Sherlock 0.16.2 | `sherlock NAME` | about 480 | 68 | 7 | 8 |

What this does and does not show:

- Maigret checked its sites slightly faster than Helix did (56 against 52 a
  second). Helix is not the fastest per site.
- Helix checked the most sites in one run, 3,057 more than Maigret, and
  finished its larger list in 70 seconds more.
- A made-up name is the kindest case for speed: with no hits, Helix's
  control probe has almost nothing to re-check. On a name with many accounts
  Helix spends extra requests confirming each one, which the other tools do
  not do. A scan of `torvalds` (132 confirmed accounts, 11,956 sites, before
  failing sites were left out) took 341 s.
- Sherlock's 8 accounts for a name nobody has are false positives from this
  address (bot-check and catch-all pages read as profiles). Helix and
  Maigret reported none in this run.
- It is one run from one network. Timeouts and bot checks depend on the
  connection, so the order can change elsewhere. `bench/compare.py` repeats
  the comparison, with a random running order, on any machine.

Helix before this work (3.7.0, same day): 12,111 sites in 326 s, 37 a
second. The gain comes from leaving out 654 sites that were dead or broken
in three checks: they were where most of the waiting was.
