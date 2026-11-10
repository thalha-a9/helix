#!/usr/bin/env python3
"""
Maltego local transform: Alias to the accounts Helix can confirm.

    python helix_transform.py USERNAME [all]

Maltego runs a local transform as a command and reads XML from its output.
The first argument is the entity's value; anything else Maltego appends
(entity fields as name=value) is ignored, except the word "all", which
scans every source instead of the built-in sites.
"""

import sys
from xml.sax.saxutils import escape


def message(entities, notes):
    """The reply Maltego expects: entities, then messages for the panel."""
    out = ["<MaltegoMessage>", "<MaltegoTransformResponseMessage>", "<Entities>"]
    for e in entities:
        out.append(f'<Entity Type="{escape(e["type"])}"><Value>{escape(e["value"])}</Value>'
                   f'<Weight>{int(e.get("weight", 100))}</Weight><AdditionalFields>')
        for name, (label, value) in e.get("fields", {}).items():
            out.append(f'<Field Name="{escape(name)}" DisplayName="{escape(label)}">{escape(str(value))}</Field>')
        out.append("</AdditionalFields></Entity>")
    out.append("</Entities><UIMessages>")
    for kind, text in notes:
        out.append(f'<UIMessage MessageType="{escape(kind)}">{escape(text)}</UIMessage>')
    out.append("</UIMessages></MaltegoTransformResponseMessage></MaltegoMessage>")
    return "\n".join(out)


def entities_for(report):
    """Website entities for the confirmed accounts, and the notes that keep
    an empty result from being read as "no accounts"."""
    weight = {"HIGH": 100, "MEDIUM": 70, "LOW": 40}
    entities = [{
        "type": "maltego.Website", "value": a["url"],
        "weight": weight.get(a.get("identity_confidence"), 40),
        "fields": {"helix.platform": ("Site", a["platform"]),
                   "helix.grade": ("Same person?", a.get("identity_confidence") or "LOW"),
                   "helix.source": ("Source", a.get("source", "")),
                   "url": ("URL", a["url"])},
    } for a in report["accounts"]]
    s = report["summary"]
    notes = [("Inform", f"Helix: {s['found']} account(s) confirmed on the {s['answered']} sites that answered.")]
    if s["unanswered"]:
        notes.append(("PartialError", f"{s['unanswered']} sites gave no clear answer; an account there "
                                      f"would not be found."))
    return entities, notes


def main(argv):
    if len(argv) < 2 or not argv[1].strip():
        print(message([], [("FatalError", "Helix transform: no username given")]))
        return 1
    sources = "all" if "all" in argv[2:] else "builtin"
    try:
        from osint.api import LeftOut, scan_sync
    except ImportError:
        print(message([], [("FatalError", "Helix is not installed for this Python: pip install helix-osint")]))
        return 1
    try:
        report = scan_sync(argv[1], sources=sources, purpose="Maltego transform")
    except LeftOut as e:
        print(message([], [("PartialError", str(e))]))
        return 0
    except ValueError as e:
        print(message([], [("FatalError", f"Helix: {e}")]))
        return 1
    print(message(*entities_for(report)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
