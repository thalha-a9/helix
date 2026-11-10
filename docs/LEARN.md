# Adding a site in one line

Helix can work out a site's rule by itself. Give it the address of a profile,
with `{username}` where the name goes:

```bash
helix --learn "https://example.com/u/{username}"
```

or, if you know an account that exists there:

```bash
helix --learn "https://example.com/u/{username}" --known alice
```

## What it does

1. It asks for three made-up names and keeps what the site answers for
   nobody. If the site gives no clear answer (a bot check, HTTP 403, a
   timeout), it stops: nothing a site says about a real account can be
   trusted when it will not say "no" for a made-up one.
2. It asks for an account that exists: the one you gave, or the first of a
   few common names (admin, john, alex and so on) that the site answers
   differently.
3. It compares the two and writes the simplest rule that separates them, in
   this order: the HTTP status, where the site redirects to, a "not found"
   text, a text only a real profile carries (for example `"login":"NAME"` in
   an API reply).
4. It runs the rule through the same engine and control probe a scan uses.
   The known account must be found and confirmed. A fresh made-up name must
   get a clear "no such user". A rule that fails is dropped and the next
   kind is tried.

It prints each step, so you can see why it chose the rule or why it learned
nothing.

## Where the site goes

The site is saved to your own list, `~/.config/helix/sites.json` (or the file
named by `--sites-file` or `$HELIX_SITES`). Every scan reads that list first,
so your sites win over the same address in a downloaded database.

To offer the site to everyone, `--learn` also prints it as one line of JSON.
Add that line to `osint/data/sites.json` in a pull request:

```json
"example.com": {"url": "https://example.com/u/{username}", "category": "other", "color": "#22c55e", "source": "own", "method": "status_code", "found": [200], "known": "alice"}
```

The `known` account stays in the line. The daily site check looks for it
every day, so a rule that stops working is noticed and the site is switched
off until it is fixed.

## What it will not learn

- A search page. It finds mentions of a name, not an account.
- A site that answers every name the same way.
- A site that only answers after a POST, a login or a browser challenge.
