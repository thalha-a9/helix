"""
Helix: fediverse servers (--fediverse, included in --all).

Mastodon, Misskey, Lemmy, PeerTube and compatible servers are separate
websites with their own users: a person on one server is not on the others.
Each server answers a username lookup in the same standard way, so one rule
per software covers all of them:

  Mastodon API   /api/v1/accounts/lookup?acct=NAME   (Mastodon, Akkoma, Pleroma,
                                                     Hometown, Iceshrimp)
  Misskey        the profile page title reads "Display name (@NAME)"
  Lemmy          /api/v3/user?username=NAME
  PeerTube       /api/v1/accounts/NAME

The server list (osint/fediverse_servers.py) is built and live-tested by
tools/update_fediverse.py. Every hit still goes through the control probe.
"""

from typing import Dict, Iterable
from urllib.parse import urlparse

from osint.fediverse_servers import GENERATED, SERVERS

MASTODON_API = {"mastodon", "hometown", "glitch-soc", "glitchsoc", "akkoma", "pleroma", "iceshrimp", "gotosocial"}
MISSKEY = {"misskey", "sharkey", "catodon", "foundkey", "firefish", "cherrypick"}

# Adult servers, reviewed by hand from the names of the servers on the list.
# Like adult sites elsewhere, they are only scanned with --nsfw. A name check
# can miss an adult server with an innocent name: report it as an issue.
NSFW = frozenset({
    "adultspace.social", "akkoma.epicboobs.sex", "bara.gallery", "kinktroet.social",
    "kinkycats.org", "lust4love.eu.org", "mastodon-sex.com", "pornanime.club",
    "send.sex", "slutty.city", "social.adultvideo.info", "social.bdsmmo.com",
    "veronaxxx.masto.host", "yiff.life",
})


def platform_for(domain: str, software: str) -> Dict:
    """Helix platform definition for one server, or {} for an unknown software."""
    base = {"category": "social", "source": "fediverse"}
    if software in MASTODON_API:
        return {**base, "url": f"https://{domain}/@{{username}}",
                "check_url": f"https://{domain}/api/v1/accounts/lookup?acct={{username}}",
                "method": "text_present", "found_text": '"username":"{username}"', "color": "#6364ff"}
    if software in MISSKEY:
        return {**base, "url": f"https://{domain}/@{{username}}",
                "method": "og_meta", "og_found": ["(@{username})"], "color": "#86b300"}
    if software == "lemmy":
        return {**base, "url": f"https://{domain}/u/{{username}}",
                "check_url": f"https://{domain}/api/v3/user?username={{username}}",
                "method": "text_present", "found_text": '"name":"{username}"', "color": "#00bc8c"}
    if software == "peertube":
        return {**base, "url": f"https://{domain}/a/{{username}}", "category": "content",
                "check_url": f"https://{domain}/api/v1/accounts/{{username}}",
                "method": "text_present", "found_text": '"name":"{username}"', "color": "#f1680d"}
    return {}


def host_of(url: str) -> str:
    host = urlparse((url or "").replace("{username}", "x")).netloc.lower().split(":")[0]
    return host[4:] if host.startswith("www.") else host


def load_platforms(include_nsfw: bool = False, skip_hosts: Iterable[str] = ()) -> Dict[str, Dict]:
    """{server domain: platform definition}, leaving out servers whose host is
    already covered (another database may list the same server)."""
    skip = {h.lower() for h in skip_hosts}
    out = {}
    for domain, software in SERVERS:
        if domain in skip or (domain in NSFW and not include_nsfw):
            continue
        pdef = platform_for(domain, software)
        if pdef:
            if domain in NSFW:
                pdef["nsfw"] = True
            out[domain] = pdef
    return out


def describe() -> str:
    return f"{len(SERVERS)} servers, list tested {GENERATED}"
