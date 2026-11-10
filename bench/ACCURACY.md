# The open accuracy test

A test of username tools on real accounts, with the owners' consent. Anyone
can re-run it. Status: the harness (`bench/compare.py`) is written and
tested; the volunteer data set does not exist yet, so there are no results
to report.

## Why it needs volunteers

The mock web in this folder measures the engine: it knows exactly which
sites have the account. The real web has no answer key. A volunteer is the
answer key: someone who writes down every site where they hold an account
under one username, and sites where they know they do not.

## What a volunteer gives

A file like this, and their written agreement that it may be published:

```json
{
  "username": "the username",
  "complete": false,
  "has": ["https://github.com/the-username", "https://lobste.rs/~the-username"],
  "has_not": ["reddit.com", "instagram.com"],
  "consent": "Name or handle, date, the sentence: I agree that this list is published and used to test username tools."
}
```

- `has`: profile addresses the volunteer confirms are theirs.
- `has_not`: sites where the volunteer confirms they have no account under
  that name (if someone else holds the name there, leave the site out).
- `complete`: true only if the volunteer is sure `has` is every account
  under that name. Then anything else a tool reports is counted as wrong.

A username that is rare (not a common first name) gives the cleanest test.

## How tools are scored

For each tool and each volunteer:

- **found**: addresses in `has` that the tool reported.
- **missed**: addresses in `has` that it did not report. A site the tool
  does not cover is counted as missed too, and listed separately, because
  coverage is part of what a user gets.
- **wrong**: reports on a `has_not` site, and, when `complete` is true, any
  report that is not in `has`.
- **unknown**: other reports. They are not counted either way.

Precision is found / (found + wrong). Recall is found / (found + missed).
Time is the wall clock of the tool's own run, all tools run one after the
other on the same machine and connection, in an order drawn at random.

## Running it

```bash
python -m bench.compare --truth volunteers/ --tools helix,sherlock,maigret \
       --results blackbird=blackbird_urls/ --out bench/results/accuracy.json
```

`helix`, `sherlock` and `maigret` are run by the harness (each must be
installed). Any other tool, such as Blackbird, is scored from a folder of
its results: one text file per username holding the profile addresses it
reported, one a line.

## Rules for publishing a result

- Every volunteer file, every tool's raw output, the versions, the date and
  the connection are published with the numbers.
- A tool is run with its documented defaults for a full scan.
- Results are reported for every tool on every volunteer, including where
  Helix does worse.
