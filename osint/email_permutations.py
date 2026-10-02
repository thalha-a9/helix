"""
Helix v3 — Email Permutation Engine
Given a username (and optional real name from confirmed profiles),
generates likely email addresses to check with holehe/breach.
"""
import re
from typing import List

_COMMON_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "protonmail.com", "icloud.com", "me.com", "aol.com",
    "mail.com", "zoho.com", "yandex.com", "tutanota.com",
]

def _clean(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', s.lower())

def _base_parts(username: str, real_name: str = "") -> List[str]:
    """Extract base parts from username and real name."""
    bases = set()
    u = username.lower()
    
    # Username as-is (cleaned)
    clean_u = re.sub(r'[^a-z0-9._\-]', '', u)
    if clean_u: bases.add(clean_u)
    
    # Username stripped of special chars
    stripped = _clean(u)
    if stripped: bases.add(stripped)
    
    # If real name provided (e.g. "Mohammad Aqib" from Dribbble)
    if real_name:
        parts = real_name.lower().split()
        if len(parts) >= 2:
            f, l = _clean(parts[0]), _clean(parts[-1])
            if f and l:
                bases.update([
                    f"{f}{l}",           # mohammadaqib
                    f"{f}.{l}",          # mohammad.aqib
                    f"{f}_{l}",          # mohammad_aqib
                    f"{f[0]}{l}",        # maqib
                    f"{f[0]}.{l}",       # m.aqib
                    f"{l}{f}",           # aqibmohammad
                    f"{l}.{f}",          # aqib.mohammad
                    # A bare first or last name (mohammad@, aqib@) is someone
                    # else's address far more often than the subject's.
                ])
    return list(bases)


def generate_email_permutations(username: str,
                                  real_name: str = "",
                                  providers: List[str] = None,
                                  max_per_provider: int = 4) -> List[str]:
    """
    Generate likely email addresses for a given username/real name.
    Returns deduplicated list sorted by likelihood.
    """
    if providers is None:
        providers = _COMMON_PROVIDERS[:6]  # top 6 by default

    bases = _base_parts(username, real_name)
    
    # Score bases by likelihood (shorter + matching username = higher priority)
    clean_u = _clean(username)
    def score(b):
        # The username first, then full-name patterns in their usual order of
        # popularity (first.last, firstlast, f.last …) — never "shortest".
        if b == clean_u: return 100
        if b.replace('.','').replace('_','') == clean_u: return 90
        order = ["{f}.{l}", "{f}{l}", "{f}_{l}", "{f0}.{l}", "{f0}{l}", "{l}.{f}", "{l}{f}"]
        if real_name and len(real_name.split()) >= 2:
            f, l = _clean(real_name.split()[0]), _clean(real_name.split()[-1])
            for i, pat in enumerate(order):
                if b == pat.format(f=f, l=l, f0=f[:1]):
                    return 80 - i
        return 0
    
    bases = sorted(set(bases), key=score, reverse=True)[:max_per_provider]

    emails = []
    for provider in providers:
        for base in bases:
            if base and re.match(r'^[a-z0-9][a-z0-9._\-]*[a-z0-9]$', base):
                emails.append(f"{base}@{provider}")

    # Deduplicate preserving order
    seen = set()
    out = []
    for e in emails:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out
