# Contributing to Helix

Thanks for wanting to help. Helix is actively maintained, and issues and pull
requests get a reply.

## Reporting problems

Use the issue forms:

* **False positive**: Helix reported an account that doesn't exist. This is
  the most useful report you can send. A made-up username that reproduces it
  is ideal, and please leave out anything about real people you investigate.
* **Site broken or missed**: a site stopped working, or Helix misses an
  account that exists.
* **Bug report**: a crash, a wrong report, an option that doesn't work.
* **Security vulnerabilities**: report them privately, see [SECURITY.md](SECURITY.md).

## Setting up

```bash
git clone https://github.com/thalha-a9/helix.git && cd helix
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,full]"
python -m pytest
```

The tests run offline and take under a minute. CI runs them on Python 3.9,
3.11, 3.12, 3.13 and 3.14.

## Adding or fixing a built-in site

Built-in sites live in `osint/platforms.py`. About 8,250 more come from the
Sherlock, WhatsMyName and Maigret databases, so a fix there helps every tool
that uses them; open it upstream when you can. The fediverse servers are a
generated list: rebuild it with `python tools/update_fediverse.py`.

For a built-in site:

1. Prefer `og_meta` or an API endpoint over `text_not_present`.
2. Check a username that cannot exist first. If Helix reports it as found,
   the rule is wrong.
3. Never point a rule at a search page: a search result can't confirm an
   account, and `tests/test_platform_schema.py` rejects them.
4. Add `bio_extract: True` and `bio_patterns` if the site renders the bio in
   the page itself.
5. Add a test in `tests/test_detection.py` with the real page title or text
   for an existing and a missing account.

## Pull requests

* One change per pull request, with a test when the change affects
  detection, verification or reports.
* `python -m pytest` must pass.
* For anything that touches detection, scan a made-up username before and
  after (`helix-osint -u <random 12 characters> --all`) and say in the pull
  request whether the number of accounts changed. It should stay at 0.
* For larger changes, open an issue first so we can agree on the approach.

By contributing you agree that your work is released under the
[MIT license](LICENSE).
