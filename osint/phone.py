"""
Helix: phone numbers (--phone), opt-in only.

    helix --phone +919876543210 --purpose "my own number"
    helix -u NAME --phone +919876543210 --breach --purpose "..."

A phone number is rarely something its owner published, so this is the most
restricted part of Helix:

  - it runs only when --phone is given, and never as part of --all or
    --pivot. --me takes it for a person checking their own number;
  - it refuses to start without --purpose;
  - only the number typed on the command line is looked at. A number seen on
    a scanned page is never looked up;
  - the left-out list covers numbers like usernames and addresses;
  - reports show the number with its middle digits hidden unless
    --show-number is given, and the sealed record never holds it in full.

What it does:

  A. Offline facts, from Google's libphonenumber data (the `phonenumbers`
     package): whether the number is valid, its country and region, the
     carrier it was issued to, the kind of line, its time zones. Nothing
     leaves the machine.
  B. Whether the accounts already found for -u show this number in the page
     Helix received. No new request is made.
  C. With --breach: whether the number appears in known breaches, asked of
     Have I Been Pwned (needs HIBP_API_KEY). A database lookup: metadata
     only, and nothing is sent to the number.

What it will never do: ask a sign-up, login or password-reset form whether
the number has an account, or check a messaging app. Those can send the
person a text, a call or an alert.

A number changes hands. Everything here is a lead about a number, not about
a person.
"""

import re
from typing import Dict, Optional

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    HAS_PHONENUMBERS = True
except ImportError:                      # the optional extra: pip install helix-osint[phone]
    HAS_PHONENUMBERS = False

INSTALL_HINT = "--phone needs the phonenumbers package: pip install helix-osint[phone]"
LEAD_NOTE = "A number changes hands: these are facts about the number, not about a person."

_LINE_TYPES = {0: "landline", 1: "mobile", 2: "landline or mobile", 3: "toll-free", 4: "premium rate",
               5: "shared cost", 6: "VoIP", 7: "personal number", 8: "pager", 9: "UAN",
               10: "voicemail", 27: "unknown", 28: "emergency", 29: "short code", 30: "standard rate"}


def parse(text: str):
    """The number as libphonenumber reads it. It must be written with its
    country code (+91...), so there is no guessing which country was meant."""
    if not HAS_PHONENUMBERS:
        raise ValueError(INSTALL_HINT)
    text = str(text or "").strip()
    if not text.startswith("+"):
        raise ValueError("write the number with its country code, for example +919876543210")
    try:
        number = phonenumbers.parse(text, None)
    except phonenumbers.NumberParseException as e:
        raise ValueError(f"not a phone number: {e}") from e
    if not phonenumbers.is_possible_number(number):
        raise ValueError("not a possible phone number for that country code")
    return number


def e164(number) -> str:
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


def masked(full: str) -> str:
    """+919876543210 as +9198xxxxx210: enough to tell two numbers apart in a
    report, not enough to call."""
    digits = full.lstrip("+")
    if len(digits) <= 6:
        return "+" + "x" * len(digits)
    return "+" + digits[:4] + "x" * (len(digits) - 7) + digits[-3:]


def facts(number) -> Dict:
    """Part A: what the number itself says. Offline."""
    return {
        "valid": phonenumbers.is_valid_number(number),
        "country_code": number.country_code,
        "country": phonenumbers.region_code_for_number(number) or "",
        "region": geocoder.description_for_number(number, "en") or "",
        "carrier_at_issue": carrier.name_for_number(number, "en") or "",
        "line_type": _LINE_TYPES.get(phonenumbers.number_type(number), "unknown"),
        "time_zones": list(timezone.time_zones_for_number(number)),
    }


def shown_in(text: str, number) -> bool:
    """Part B: the page shows this number, however it is spaced or
    punctuated, with or without the country code. The national number must
    stand alone, not sit inside a longer run of digits."""
    national = str(number.national_number)
    if not text or len(national) < 7:
        return False
    body = r"[\s().\- ]*".join(re.escape(d) for d in national)
    return re.search(r"(?<!\d)(?:\+?" + str(number.country_code) + r"[\s().\- ]*|0)?" + body + r"(?!\d)",
                     text) is not None


def describe(info: Dict) -> str:
    """One line for the terminal."""
    if not info["valid"]:
        return "not a valid number for its country code (it may be mistyped or never issued)"
    parts = [info["line_type"]]
    where = ", ".join(p for p in (info["region"], info["country"]) if p)
    if where:
        parts.append(where)
    if info["carrier_at_issue"]:
        parts.append(f"issued to {info['carrier_at_issue']} (numbers can move to another carrier)")
    if info["time_zones"]:
        parts.append("time zone " + ", ".join(info["time_zones"][:2]))
    return "; ".join(parts)


def report(text: str, show: bool = False) -> Optional[Dict]:
    """Everything part A knows, as it goes into reports."""
    number = parse(text)
    full = e164(number)
    return {"number": full if show else masked(full), "shown_in_full": bool(show),
            **facts(number), "note": LEAD_NOTE, "_number": number, "_e164": full}
