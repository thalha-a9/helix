"""
Helix: the left-out list.

Anyone can ask that their username or email address is not looked up with
Helix. Names on the list are refused before a single request is sent, and no
option turns that off.

The list holds no names. Each entry is a token made from the name with
PBKDF2-HMAC-SHA256 (200,000 rounds, a fixed public salt), so the published
list does not tell a reader who is on it, and checking one name costs a
fraction of a second while trying millions of guesses costs days. It is
still a hash of something guessable: a person who already suspects a name
can test it. The list says so where people ask to be added.

    helix --left-out-token NAME      # the token to send with a request

A request is an issue with the token (see docs/LEFT_OUT.md); the maintainer
adds it to helix_osint/data/left_out.json. The list ships with every release and
scans that download the site databases also pick up the day's copy.

Helix is open source. Someone who removes this check from their own copy can
scan anyone; the list binds the official tool and people who use it as
published, which is most of them.
"""

import hashlib
from pathlib import Path
from typing import Optional, Set

SCHEMA = "helix.left-out.v1"
SALT = b"helix-left-out-v1"
ROUNDS = 200_000

SHIPPED = Path(__file__).parent / "data" / "left_out.json"
LIST_URL = "https://raw.githubusercontent.com/thalha-a9/helix/main/helix_osint/data/left_out.json"
_CACHE = Path.home() / ".cache" / "helix" / "left_out_v1.json"

REFUSAL = ("is on the left-out list: its owner asked not to be looked up with Helix. "
           "Nothing was requested.")


def normalise(identifier: str) -> str:
    """A username or address as it is compared: no @ in front, lower case."""
    return str(identifier or "").strip().lstrip("@").lower()


def token(identifier: str) -> str:
    """The list entry for a username or an email address."""
    return hashlib.pbkdf2_hmac("sha256", normalise(identifier).encode("utf-8"), SALT, ROUNDS).hex()


def _valid(data) -> bool:
    return (isinstance(data, dict) and data.get("schema") == SCHEMA
            and isinstance(data.get("tokens"), list)
            and all(isinstance(t, str) and len(t) == 64 for t in data["tokens"]))


def load() -> Set[str]:
    """Every token at hand: the shipped list and the last download together,
    so a name stays left out whichever copy is older."""
    from helix_osint.updates import read_json
    tokens: Set[str] = set()
    for path in (SHIPPED, _CACHE):
        data = read_json(path, _valid)
        if data:
            tokens.update(t.lower() for t in data["tokens"])
    return tokens


async def refresh(timeout: float = 8.0, url: str = LIST_URL) -> bool:
    from helix_osint.updates import fetch_daily
    return await fetch_daily(url, _CACHE, _valid, timeout=timeout)


def is_left_out(identifier: str, tokens: Optional[Set[str]] = None) -> bool:
    tokens = load() if tokens is None else tokens
    return bool(tokens) and bool(normalise(identifier)) and token(identifier) in tokens
