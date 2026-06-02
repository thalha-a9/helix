"""
OSINT Grapher v2.0 — Username Permutation Generator
Generates common variations a target might use across platforms.
"""

import re
from typing import List


def generate_permutations(username: str) -> List[str]:
    """
    Generate common username permutations.
    Returns a sorted list of variations (excluding the original).
    """
    perms: set = set()
    u = username.lower()

    # Separator-based splits (for camelCase or compoundnames)
    # e.g. JohnDoe → john_doe, john.doe, johndoe
    snake = re.sub(r'(?<=[a-z])(?=[A-Z])', '_', username).lower()
    dot   = re.sub(r'(?<=[a-z])(?=[A-Z])', '.', username).lower()
    if snake != u:
        perms.add(snake)
    if dot != u:
        perms.add(dot)

    # Common numeric suffixes
    for suffix in ["1", "2", "123", "1337", "99", "01"]:
        perms.add(u + suffix)
        perms.add(username + suffix)

    # Common symbol suffixes / prefixes
    for sym in ["_", ".", "-"]:
        perms.add(u + sym)
        if not u.startswith(sym):
            perms.add(sym + u)

    # Common word prefixes
    for prefix in ["real", "the", "official", "iam", "i_am", "its"]:
        perms.add(prefix + u)
        perms.add(prefix + "_" + u)
        perms.add(prefix + "." + u)

    # Common word suffixes
    for suffix in ["official", "_", "hq", "real", "dev", "xyz", "io", "gg"]:
        perms.add(u + suffix)
        perms.add(u + "_" + suffix)

    # Separator replacement (for usernames that already have separators)
    if "_" in u:
        perms.add(u.replace("_", "."))
        perms.add(u.replace("_", ""))
        perms.add(u.replace("_", "-"))
    if "." in u:
        perms.add(u.replace(".", "_"))
        perms.add(u.replace(".", ""))
        perms.add(u.replace(".", "-"))

    # Strip trailing digits to get base name variant
    stripped = re.sub(r'\d+$', '', u)
    if stripped and stripped != u and len(stripped) >= 2:
        perms.add(stripped)

    # Remove original username and filter invalid
    perms.discard(username)
    perms.discard(u)
    perms.discard("")

    # Filter to valid username characters and reasonable length
    valid = [
        p for p in perms
        if re.match(r'^[a-zA-Z0-9._\-]+$', p) and 1 < len(p) <= 50
    ]

    return sorted(valid)
