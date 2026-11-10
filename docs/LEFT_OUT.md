# Being left out

You can ask that your username or email address is never looked up with
Helix. Names on the list are refused before a single request is sent, and no
option turns that off.

## How to ask

1. On your own computer, run:

   ```bash
   helix --left-out-token YOURNAME
   ```

   It prints 64 characters. Your name is not sent anywhere.
2. Open a "Leave me out" issue on <https://github.com/thalha-a9/helix/issues>
   and paste the 64 characters. Do not write the name itself: the issue is
   public.
3. Do this once for each username or address.

If you cannot run Helix, ask someone you trust to run the command for you,
or write to the maintainer through the address in `SECURITY.md`.

## How it works

The list (`osint/data/left_out.json`) holds tokens, not names. A token is
made from the lower-case name with PBKDF2-HMAC-SHA256, 200,000 rounds and a
fixed public salt. Before a scan, Helix makes the token for the name it was
given and stops if the token is on the list. The same check covers the email
address, the variants `--permutations` would scan and the aliases `--pivot`
would follow.

The list ships with every release. Scans that download the site databases
also fetch the day's copy.

## What it does and does not do

- It stops the published Helix from looking a listed name up.
- It does not hide the name from other tools, and it does not remove any
  account. To delete accounts, see `helix --me`.
- A token cannot be turned back into a name, but it is a hash of something
  guessable. Someone who already suspects a name can make its token and
  compare. The slow hash makes trying millions of guesses expensive; it does
  not make one guess expensive.
- Helix is open source. Someone who removes the check from their own copy
  can scan anyone. The list binds the tool as published.

## Coming off the list

Open an issue with the same token and say you want it removed.
