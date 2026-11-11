"""
SpiderFoot module: usernames to the accounts Helix can confirm.

Copy this file into SpiderFoot's modules/ folder. It needs Helix installed
in the same Python (pip install helix-osint).
"""

try:
    from spiderfoot import SpiderFootEvent, SpiderFootPlugin
except ImportError:                      # outside SpiderFoot (tests, linting)
    SpiderFootPlugin = object
    SpiderFootEvent = None


class sfp_helix(SpiderFootPlugin):

    meta = {
        "name": "Helix",
        "summary": "Find accounts under a username, each confirmed live against made-up names.",
        "flags": ["slow"],
        "useCases": ["Footprint", "Passive"],
        "categories": ["Social Media"],
        "dataSource": {
            "website": "https://github.com/thalha-a9/helix",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": ["https://github.com/thalha-a9/helix#readme"],
            "description": "Helix checks a username on the Sherlock, WhatsMyName and Maigret "
                           "site lists and on fediverse servers, and reports an account only "
                           "after the site refused made-up names.",
        },
    }

    opts = {"sources": "builtin", "purpose": "SpiderFoot scan"}
    optdescs = {
        "sources": "Where to look: builtin (56 sites, fast) or all (about 12,000 sites, minutes).",
        "purpose": "Why the scan is run; passed to Helix.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage() if hasattr(self, "tempStorage") else {}
        self.errorState = False
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["USERNAME"]

    def producedEvents(self):
        return ["ACCOUNT_EXTERNAL_OWNED", "SOCIAL_MEDIA"]

    @staticmethod
    def events_for(report):
        """(event type, data) for every confirmed account."""
        out = []
        for a in report["accounts"]:
            out.append(("ACCOUNT_EXTERNAL_OWNED", f"{a['platform']} (Category: {a.get('category', 'other')})\n"
                                                  f"<SFURL>{a['url']}</SFURL>"))
            if a.get("category") == "social":
                out.append(("SOCIAL_MEDIA", f"{a['platform']}: <SFURL>{a['url']}</SFURL>"))
        return out

    def handleEvent(self, event):
        username = event.data
        if self.errorState or username in self.results:
            return
        self.results[username] = True
        try:
            from helix_osint.api import LeftOut, scan_sync
        except ImportError:
            self.error("Helix is not installed for this Python: pip install helix-osint")
            self.errorState = True
            return
        try:
            report = scan_sync(username, sources=self.opts["sources"], purpose=self.opts["purpose"])
        except LeftOut as e:
            self.info(str(e))
            return
        except ValueError as e:
            self.debug(f"Helix skipped {username}: {e}")
            return
        s = report["summary"]
        if s["unanswered"]:
            self.info(f"Helix: {s['unanswered']} of {s['attempted']} sites gave no clear answer for {username}")
        for kind, data in self.events_for(report):
            self.notifyListeners(SpiderFootEvent(kind, data, self.__name__, event))
